package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func startSOCKS(t *testing.T, dial dialFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveSOCKS(ln, dial)
	return ln.Addr().String()
}

func TestSOCKSRelaysThroughDial(t *testing.T) {
	echo := startEcho(t)
	var mu sync.Mutex
	var asked string
	addr := startSOCKS(t, func(network, target string) (net.Conn, error) {
		mu.Lock()
		asked = target
		mu.Unlock()
		return net.Dial(network, echo)
	})

	client, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial("tcp", "some.example.com:443")
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q", buf)
	}
	mu.Lock()
	defer mu.Unlock()
	if asked != "some.example.com:443" {
		t.Fatalf("server resolved target %q, want the domain passed through", asked)
	}
}

func TestSOCKSAddressTypes(t *testing.T) {
	tests := []struct {
		name string
		req  []byte
		want string
	}{
		{"ipv4", []byte{5, 1, 0, 1, 1, 2, 3, 4, 0x01, 0xBB}, "1.2.3.4:443"},
		{"domain", append(append([]byte{5, 1, 0, 3, 3}, "a.b"...), 0, 80), "a.b:80"},
		{"ipv6", append(append([]byte{5, 1, 0, 4}, net.ParseIP("2001:db8::1")...), 0, 80), "[2001:db8::1]:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := make(chan string, 1)
			addr := startSOCKS(t, func(_, target string) (net.Conn, error) {
				got <- target
				return nil, errors.New("stop here")
			})
			conn := socksHello(t, addr)
			defer conn.Close()
			conn.Write(tt.req)
			select {
			case target := <-got:
				if target != tt.want {
					t.Fatalf("target = %q, want %q", target, tt.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("dial was not called")
			}
		})
	}
}

func socksHello(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("greeting reply = %v, want no-auth", reply)
	}
	return conn
}

func TestSOCKSReportsDialFailure(t *testing.T) {
	addr := startSOCKS(t, func(_, _ string) (net.Conn, error) {
		return nil, errors.New("tunnel down")
	})
	conn := socksHello(t, addr)
	defer conn.Close()
	conn.Write([]byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if reply[1] != 1 {
		t.Fatalf("reply code = %d, want 1 (general failure)", reply[1])
	}
}

func TestSOCKSRejectsUnsupportedCommand(t *testing.T) {
	called := make(chan struct{}, 1)
	addr := startSOCKS(t, func(_, _ string) (net.Conn, error) {
		called <- struct{}{}
		return nil, errors.New("no")
	})
	conn := socksHello(t, addr)
	defer conn.Close()
	conn.Write([]byte{5, 2, 0, 1, 1, 2, 3, 4, 0, 80}) // BIND
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if reply[1] != 7 {
		t.Fatalf("reply code = %d, want 7 (command not supported)", reply[1])
	}
	select {
	case <-called:
		t.Fatal("dial must not run for unsupported commands")
	default:
	}
}

func TestSOCKSRejectsClientsThatRequireAuth(t *testing.T) {
	addr := startSOCKS(t, func(_, _ string) (net.Conn, error) { return nil, errors.New("no") })
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte{5, 1, 2}) // username/password only
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if reply[1] != 0xFF {
		t.Fatalf("method = %d, want 0xFF", reply[1])
	}
}

func TestSOCKSStopsWhenListenerCloses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { serveSOCKS(ln, nil); close(done) }()
	ln.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveSOCKS did not return")
	}
}
