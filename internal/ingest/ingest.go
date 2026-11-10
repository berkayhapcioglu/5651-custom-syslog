// Package ingest receives syslog over UDP, TCP and TLS (RFC 5424/3164
// payloads, RFC 6587 framing on streams) and hands records to the store.
//
// Messages are stored byte for byte as received; nothing is parsed or
// rewritten, because the stored text is the legal evidence.
package ingest

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
)

// Resolver maps a source address to a tenant.
type Resolver func(netip.Addr) (string, bool)

// Server runs the listeners.
type Server struct {
	Resolve     Resolver
	Out         chan<- store.Record
	Log         *slog.Logger
	MaxMsg      int
	MaxConns    int
	IdleTimeout time.Duration

	Dropped  atomic.Int64 // unknown sources
	TooLong  atomic.Int64 // truncated messages
	Rejected atomic.Int64 // connections over the limit or from unknown sources

	conns chan struct{}
	wg    sync.WaitGroup
}

func (s *Server) init() {
	if s.conns == nil {
		s.conns = make(chan struct{}, s.MaxConns)
	}
}

func (s *Server) emit(src netip.Addr, msg []byte) {
	tenant, ok := s.Resolve(src)
	if !ok {
		s.Dropped.Add(1)
		return
	}
	if len(msg) > s.MaxMsg {
		msg = msg[:s.MaxMsg]
		s.TooLong.Add(1)
	}
	s.Out <- store.Record{Received: time.Now(), Source: src.Unmap(), Tenant: tenant, Message: append([]byte(nil), msg...)}
}

// ServeUDP listens on addr until ctx ends.
func (s *Server) ServeUDP(ctx context.Context, addr string) error {
	s.init()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	if u, ok := pc.(*net.UDPConn); ok {
		_ = u.SetReadBuffer(16 << 20)
	}
	s.Log.Info("listening", "proto", "udp", "addr", pc.LocalAddr().String())
	go func() { <-ctx.Done(); pc.Close() }()
	u := pc.(*net.UDPConn)
	buf := make([]byte, 65536)
	for {
		n, ap, err := u.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.Log.Warn("udp read", "err", err)
			continue
		}
		s.emit(ap.Addr(), buf[:n])
	}
}

// ServeTCP listens for plain TCP until ctx ends.
func (s *Server) ServeTCP(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.Log.Info("listening", "proto", "tcp", "addr", ln.Addr().String())
	return s.serve(ctx, ln)
}

// TLSConfig builds a hardened server TLS config. With clientCA set, clients
// must present a certificate signed by it.
func TLSConfig(certFile, keyFile, clientCA string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{ // TLS 1.2 only; TLS 1.3 suites are always safe
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	if clientCA != "" {
		b, err := os.ReadFile(clientCA) // #nosec G304 -- operator-supplied path
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("tls_client_ca: no certificates found")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// ServeTLS listens for syslog over TLS (RFC 5425) until ctx ends.
func (s *Server) ServeTLS(ctx context.Context, addr string, cfg *tls.Config) error {
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return err
	}
	s.Log.Info("listening", "proto", "tls", "addr", ln.Addr().String())
	return s.serve(ctx, ln)
}

func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	s.init()
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil {
			c.Close()
			continue
		}
		// Refuse unknown sources before reading anything.
		if _, ok := s.Resolve(ap.Addr()); !ok {
			s.Rejected.Add(1)
			c.Close()
			continue
		}
		select {
		case s.conns <- struct{}{}:
		default:
			s.Rejected.Add(1)
			c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.conns }()
			defer c.Close()
			if err := s.handle(ctx, c, ap.Addr()); err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.Log.Debug("connection closed", "remote", ap.String(), "err", err)
			}
		}()
	}
}

// handle reads RFC 6587 frames: octet counting ("123 <msg>") or
// newline-delimited (non-transparent framing).
func (s *Server) handle(ctx context.Context, c net.Conn, src netip.Addr) error {
	br := bufio.NewReaderSize(c, 64*1024)
	for ctx.Err() == nil {
		if err := c.SetReadDeadline(time.Now().Add(s.IdleTimeout)); err != nil {
			return err
		}
		first, err := br.Peek(1)
		if err != nil {
			return err
		}
		if first[0] >= '1' && first[0] <= '9' {
			msg, err := s.readOctetCounted(br)
			if err != nil {
				return err
			}
			s.emit(src, msg)
			continue
		}
		msg, err := s.readLine(br)
		if err != nil {
			return err
		}
		if len(msg) > 0 {
			s.emit(src, msg)
		}
	}
	return ctx.Err()
}

func (s *Server) readOctetCounted(br *bufio.Reader) ([]byte, error) {
	n := 0
	for i := 0; ; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == ' ' {
			break
		}
		if b < '0' || b > '9' || i >= 7 {
			return nil, fmt.Errorf("bad octet count")
		}
		n = n*10 + int(b-'0')
	}
	if n == 0 || n > 8*1024*1024 {
		return nil, fmt.Errorf("frame length %d out of range", n)
	}
	keep := min(n, s.MaxMsg)
	msg := make([]byte, keep)
	if _, err := io.ReadFull(br, msg); err != nil {
		return nil, err
	}
	if n > keep {
		s.TooLong.Add(1)
		if _, err := br.Discard(n - keep); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

func (s *Server) readLine(br *bufio.Reader) ([]byte, error) {
	var msg []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(msg)+len(chunk) <= s.MaxMsg+1 {
			msg = append(msg, chunk...)
		} else if len(msg) <= s.MaxMsg {
			msg = append(msg, chunk[:s.MaxMsg+1-len(msg)]...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if len(msg) > 0 && errors.Is(err, io.EOF) {
				return msg, nil
			}
			return nil, err
		}
		if len(msg) > 0 && msg[len(msg)-1] == '\n' {
			msg = msg[:len(msg)-1]
		}
		if len(msg) > 0 && msg[len(msg)-1] == '\r' {
			msg = msg[:len(msg)-1]
		}
		return msg, nil
	}
}
