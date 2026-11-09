package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testServer is a real SSH server with direct-tcpip forwarding.
type testServer struct {
	ln       net.Listener
	addr     string
	config   *ssh.ServerConfig
	mu       sync.Mutex
	conns    []net.Conn
	hostKeys []ssh.Signer
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newECDSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func startServer(t *testing.T, client ssh.PublicKey, hostKeys ...ssh.Signer) *testServer {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(client.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("key not allowed")
		},
	}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{ln: ln, addr: ln.Addr().String(), config: cfg, hostKeys: hostKeys}
	t.Cleanup(s.stop)
	go s.acceptLoop()
	return s
}

func (s *testServer) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		go s.handle(c)
	}
}

func (s *testServer) handle(c net.Conn) {
	sc, chans, reqs, err := ssh.NewServerConn(c, s.config)
	if err != nil {
		return
	}
	defer sc.Close()
	go func() {
		for r := range reqs {
			if r.WantReply {
				r.Reply(true, nil)
			}
		}
	}()
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		go forward(nc)
	}
}

func forward(nc ssh.NewChannel) {
	data := nc.ExtraData()
	n := binary.BigEndian.Uint32(data[:4])
	host := string(data[4 : 4+n])
	port := binary.BigEndian.Uint32(data[4+n : 8+n])
	dst, err := net.Dial("tcp", net.JoinHostPort(host, itoa(int(port))))
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		dst.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { io.Copy(ch, dst); ch.Close() }()
	go func() { io.Copy(dst, ch); dst.Close() }()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func (s *testServer) stop() {
	s.ln.Close()
	s.dropConns()
}

func (s *testServer) dropConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = nil
}

func writeKnownHosts(t *testing.T, addr string, keys ...ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(knownhosts.Line([]string{knownhosts.Normalize(addr)}, k) + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testTarget(addr string, signer ssh.Signer, knownHosts string) *target {
	return &target{
		addr:         addr,
		user:         "root",
		signer:       signer,
		knownHosts:   knownHosts,
		dialTimeout:  3 * time.Second,
		pingInterval: time.Hour,
		pingTimeout:  time.Hour,
		confirm:      func(string) (bool, error) { return false, errors.New("unexpected prompt") },
	}
}

func TestConnectForwardsThroughTunnel(t *testing.T) {
	client, host := newSigner(t), newSigner(t)
	srv := startServer(t, client.PublicKey(), host)
	tgt := testTarget(srv.addr, client, writeKnownHosts(t, srv.addr, host.PublicKey()))

	sess, err := tgt.connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sess.Close()

	conn, err := sess.Dial("tcp", startEcho(t))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestConnectMatchesKnownKeyOfEitherType(t *testing.T) {
	client := newSigner(t)
	ed, ec := newSigner(t), newECDSASigner(t)
	tests := []struct {
		name  string
		known ssh.PublicKey
	}{
		{"only ed25519 known", ed.PublicKey()},
		{"only ecdsa known", ec.PublicKey()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, client.PublicKey(), ed, ec)
			tgt := testTarget(srv.addr, client, writeKnownHosts(t, srv.addr, tt.known))
			sess, err := tgt.connect(context.Background())
			if err != nil {
				t.Fatalf("a server with several host keys must not look changed: %v", err)
			}
			sess.Close()
		})
	}
}

func TestConnectAsksOnceForUnknownHost(t *testing.T) {
	client, host := newSigner(t), newSigner(t)
	srv := startServer(t, client.PublicKey(), host)
	known := filepath.Join(t.TempDir(), "sub", "known_hosts") // file and folder do not exist yet
	tgt := testTarget(srv.addr, client, known)
	asked := 0
	tgt.confirm = func(prompt string) (bool, error) {
		asked++
		if !strings.Contains(prompt, ssh.FingerprintSHA256(host.PublicKey())) {
			t.Errorf("prompt %q should show the fingerprint", prompt)
		}
		return true, nil
	}

	for i := 0; i < 2; i++ {
		sess, err := tgt.connect(context.Background())
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		sess.Close()
	}
	if asked != 1 {
		t.Fatalf("asked %d times, want 1", asked)
	}
}

func TestConnectAddsToExistingKnownHostsWithoutNewline(t *testing.T) {
	client, host := newSigner(t), newSigner(t)
	srv := startServer(t, client.PublicKey(), host)
	other := newSigner(t)
	known := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"other.example"}, other.PublicKey())
	if err := os.WriteFile(known, []byte(line), 0o600); err != nil { // no trailing newline
		t.Fatal(err)
	}
	tgt := testTarget(srv.addr, client, known)
	tgt.confirm = func(string) (bool, error) { return true, nil }
	sess, err := tgt.connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sess.Close()

	cb, err := knownhosts.New(known)
	if err != nil {
		t.Fatalf("known_hosts is now unreadable: %v", err)
	}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if err := cb("other.example:22", remote, other.PublicKey()); err != nil {
		t.Fatalf("existing entry was damaged: %v", err)
	}
	if err := cb(srv.addr, remote, host.PublicKey()); err != nil {
		t.Fatalf("new entry missing: %v", err)
	}
}

func TestConnectDecliningUnknownHostIsFatal(t *testing.T) {
	client, host := newSigner(t), newSigner(t)
	srv := startServer(t, client.PublicKey(), host)
	known := filepath.Join(t.TempDir(), "known_hosts")
	tgt := testTarget(srv.addr, client, known)
	tgt.confirm = func(string) (bool, error) { return false, nil }

	_, err := tgt.connect(context.Background())
	assertFatal(t, err)
	if data, _ := os.ReadFile(known); len(data) != 0 {
		t.Fatalf("declined host was recorded: %q", data)
	}
}

func TestConnectChangedHostKeyIsFatalAndNeverAsks(t *testing.T) {
	client, host := newSigner(t), newSigner(t)
	srv := startServer(t, client.PublicKey(), host)
	known := writeKnownHosts(t, srv.addr, newSigner(t).PublicKey())
	before, _ := os.ReadFile(known)
	tgt := testTarget(srv.addr, client, known)

	_, err := tgt.connect(context.Background())
	assertFatal(t, err)
	if !strings.Contains(strings.ToLower(err.Error()), "changed") {
		t.Fatalf("error should warn the key changed: %v", err)
	}
	after, _ := os.ReadFile(known)
	if string(before) != string(after) {
		t.Fatal("known_hosts must not be modified on a mismatch")
	}
}

func TestConnectRejectedKeyIsFatal(t *testing.T) {
	allowed, host := newSigner(t), newSigner(t)
	srv := startServer(t, allowed.PublicKey(), host)
	tgt := testTarget(srv.addr, newSigner(t), writeKnownHosts(t, srv.addr, host.PublicKey()))
	_, err := tgt.connect(context.Background())
	assertFatal(t, err)
}

func TestConnectServerDownIsRetryable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	tgt := testTarget(addr, newSigner(t), writeKnownHosts(t, addr))
	_, err = tgt.connect(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	var fatal *fatalError
	if errors.As(err, &fatal) {
		t.Fatalf("network failures must be retryable: %v", err)
	}
}

func TestConnectGivesUpOnSilentServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0") // accepts TCP, never speaks SSH
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	tgt := testTarget(addr, newSigner(t), writeKnownHosts(t, addr))
	tgt.dialTimeout = 100 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := tgt.connect(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a timeout")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("connect hung on a server that never answers")
	}
}

func TestSessionWaitReturnsWhenServerDrops(t *testing.T) {
	client, host := newSigner(t), newSigner(t)
	srv := startServer(t, client.PublicKey(), host)
	tgt := testTarget(srv.addr, client, writeKnownHosts(t, srv.addr, host.PublicKey()))
	sess, err := tgt.connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	srv.dropConns()
	assertWaitReturns(t, sess)
}

// blackhole relays TCP until freeze is called, then stops moving bytes
// while keeping both sockets open, like a network that silently vanished.
type blackhole struct {
	addr   string
	mu     sync.Mutex
	frozen bool
}

func startBlackhole(t *testing.T, upstream string) *blackhole {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	b := &blackhole{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", upstream)
			if err != nil {
				c.Close()
				return
			}
			t.Cleanup(func() { c.Close(); up.Close() })
			go b.pump(c, up)
			go b.pump(up, c)
		}
	}()
	return b
}

func (b *blackhole) pump(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		b.mu.Lock()
		frozen := b.frozen
		b.mu.Unlock()
		if frozen {
			continue
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (b *blackhole) freeze() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.frozen = true
}

func TestSessionDetectsSilentlyDeadNetwork(t *testing.T) {
	client, host := newSigner(t), newSigner(t)
	srv := startServer(t, client.PublicKey(), host)
	hole := startBlackhole(t, srv.addr)
	tgt := testTarget(hole.addr, client, writeKnownHosts(t, hole.addr, host.PublicKey()))
	tgt.pingInterval = 20 * time.Millisecond
	tgt.pingTimeout = 100 * time.Millisecond

	sess, err := tgt.connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// Healthy pings must keep the session alive well past one timeout.
	select {
	case <-waitChan(sess):
		t.Fatal("session died while the network was healthy")
	case <-time.After(300 * time.Millisecond):
	}

	hole.freeze()
	assertWaitReturns(t, sess)
}

func waitChan(s session) <-chan struct{} {
	ch := make(chan struct{})
	go func() { s.Wait(); close(ch) }()
	return ch
}

func assertWaitReturns(t *testing.T, s session) {
	t.Helper()
	select {
	case <-waitChan(s):
	case <-time.After(3 * time.Second):
		t.Fatal("Wait did not return after the connection died")
	}
}

func assertFatal(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	var fatal *fatalError
	if !errors.As(err, &fatal) {
		t.Fatalf("want a fatal error, got %T: %v", err, err)
	}
}

// --- key loading ---

func writeKey(t *testing.T, passphrase string) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return path, sshPub
}

func TestLoadSignerWithoutPassphraseDoesNotPrompt(t *testing.T) {
	path, pub := writeKey(t, "")
	signer, err := loadSigner(path, func(string) ([]byte, error) {
		t.Fatal("must not prompt")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(signer.PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Fatal("wrong key loaded")
	}
}

func TestLoadSignerDecryptsWithPassphrase(t *testing.T) {
	path, pub := writeKey(t, "correct horse")
	signer, err := loadSigner(path, func(string) ([]byte, error) { return []byte("correct horse"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if string(signer.PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Fatal("wrong key loaded")
	}
}

func TestLoadSignerWrongPassphraseIsFatal(t *testing.T) {
	path, _ := writeKey(t, "correct horse")
	calls := 0
	_, err := loadSigner(path, func(string) ([]byte, error) { calls++; return []byte("nope"), nil })
	assertFatal(t, err)
	if !strings.Contains(strings.ToLower(err.Error()), "passphrase") {
		t.Fatalf("error should mention the passphrase: %v", err)
	}
	if calls != 1 {
		t.Fatalf("prompted %d times, want 1", calls)
	}
}

func TestLoadSignerMissingFileNamesThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	_, err := loadSigner(path, nil)
	assertFatal(t, err)
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error should name %s: %v", path, err)
	}
}
