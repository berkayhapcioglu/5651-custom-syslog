// Package smtptest is a tiny SMTP server for tests.
package smtptest

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"sync"
)

// Server accepts mail and keeps the DATA of each message.
type Server struct {
	Addr string
	TLS  *tls.Config // offers STARTTLS when set

	mu   sync.Mutex
	msgs []string
	ln   net.Listener
}

// Start listens on 127.0.0.1.
func Start(tc *tls.Config) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{Addr: ln.Addr().String(), TLS: tc, ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s, nil
}

// Close stops the server.
func (s *Server) Close() { s.ln.Close() }

// Messages returns the received messages.
func (s *Server) Messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}

func (s *Server) serve(c net.Conn) {
	defer func() { c.Close() }()
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(l string) { w.WriteString(l + "\r\n"); w.Flush() }
	say("220 test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			if s.TLS != nil {
				if _, ok := c.(*tls.Conn); !ok {
					say("250-test")
					say("250 STARTTLS")
					continue
				}
			}
			say("250 test")
		case cmd == "STARTTLS" && s.TLS != nil:
			say("220 go ahead")
			tc := tls.Server(c, s.TLS)
			if tc.Handshake() != nil {
				return
			}
			c = tc
			r, w = bufio.NewReader(c), bufio.NewWriter(c)
		case cmd == "DATA":
			say("354 send")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, b.String())
			s.mu.Unlock()
			say("250 ok")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}
