package ingest

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/berkayhapcioglu/5651-custom-syslog/internal/store"
)

// pair returns a connected loopback TCP pair; the client side gets data and is closed.
func pair(t *testing.T, data []byte) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		c.Write(data)
		c.Close()
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func newServer(out chan store.Record, allow bool) *Server {
	return &Server{
		Resolve:     func(netip.Addr) (string, bool) { return "musteri-a", allow },
		Out:         out,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxMsg:      64,
		MaxConns:    4,
		IdleTimeout: 5 * time.Second,
	}
}

func TestFraming(t *testing.T) {
	out := make(chan store.Record, 16)
	s := newServer(out, true)
	var got []string
	in := "12 <13>hello\nab" + "<14>plain line\r\n" + "<15>no newline at eof"
	// "12 <13>hello\nab": octet counted frame of 12 bytes = "<13>hello\nab"
	s.handle(context.Background(), pair(t, []byte(in)), netip.MustParseAddr("10.0.0.1"))
	close(out)
	for r := range out {
		got = append(got, string(r.Message))
	}
	want := []string{"<13>hello\nab", "<14>plain line", "<15>no newline at eof"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("frame %d: %q want %q", i, got[i], want[i])
		}
	}
}

func TestTruncation(t *testing.T) {
	out := make(chan store.Record, 4)
	s := newServer(out, true)
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'x'
	}
	s.handle(context.Background(), pair(t, append(append(long, '\n'), "short\n"...)), netip.MustParseAddr("10.0.0.1"))
	r := <-out
	if len(r.Message) != 64 || s.TooLong.Load() == 0 {
		t.Fatalf("not truncated: %d", len(r.Message))
	}
	if r := <-out; string(r.Message) != "short" {
		t.Fatalf("next message corrupted: %q", r.Message)
	}
}

func TestBadOctetCount(t *testing.T) {
	s := newServer(make(chan store.Record, 1), true)
	if err := s.handle(context.Background(), pair(t, []byte("99999999999 x")), netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Fatal("expected error for absurd frame length")
	}
}

func TestTCPRejectsUnknownSource(t *testing.T) {
	out := make(chan store.Record, 1)
	s := newServer(out, false)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.serve(ctx, ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hello\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := bufio.NewReader(c).ReadByte(); err == nil {
		t.Fatal("connection from unknown source stayed open")
	}
	if s.Rejected.Load() != 1 || len(out) != 0 {
		t.Fatal("unknown source was not rejected")
	}
}

func TestUDP(t *testing.T) {
	out := make(chan store.Record, 1)
	s := newServer(out, true)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.ServeUDP(ctx, addr)
	time.Sleep(100 * time.Millisecond)
	c, _ := net.Dial("udp", addr)
	c.Write([]byte("<13>udp test"))
	select {
	case r := <-out:
		if string(r.Message) != "<13>udp test" || r.Tenant != "musteri-a" {
			t.Fatalf("got %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no udp record")
	}
}
