package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// target is everything needed to open a session to the server.
type target struct {
	addr         string
	user         string
	signer       ssh.Signer
	knownHosts   string
	dialTimeout  time.Duration
	pingInterval time.Duration
	pingTimeout  time.Duration
	confirm      func(prompt string) (bool, error)
}

func (t *target) connect(ctx context.Context) (session, error) {
	check, err := knownHostsChecker(t.knownHosts)
	if err != nil {
		return nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", t.addr)
	if err != nil {
		return nil, err
	}
	stopWatching := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopWatching()
	conn.SetDeadline(time.Now().Add(t.dialTimeout))

	config := &ssh.ClientConfig{
		User:              t.user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(t.signer)},
		HostKeyCallback:   t.hostKeyCallback(check, conn),
		HostKeyAlgorithms: knownKeyAlgorithms(check, t.addr),
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, t.addr, config)
	if err != nil {
		conn.Close()
		return nil, classifyHandshake(err)
	}
	conn.SetDeadline(time.Time{})
	return newSSHSession(ssh.NewClient(c, chans, reqs), t.pingInterval, t.pingTimeout), nil
}

func classifyHandshake(err error) error {
	var fatal *fatalError
	if errors.As(err, &fatal) {
		return fatal
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return fatalf("the server rejected your key. Check that its public key is in the server's authorized_keys.")
	}
	return err
}

// knownHostsChecker loads the file, creating an empty one if it is missing.
func knownHostsChecker(path string) (ssh.HostKeyCallback, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fatalf("cannot create %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return nil, fatalf("cannot create %s: %v", path, err)
		}
	}
	check, err := knownhosts.New(path)
	if err != nil {
		return nil, fatalf("cannot read %s: %v", path, err)
	}
	return check, nil
}

func (t *target) hostKeyCallback(check ssh.HostKeyCallback, conn net.Conn) ssh.HostKeyCallback {
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := check(host, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return fatalf("server key rejected: %v", err)
		}
		if len(keyErr.Want) > 0 {
			return fatalf("WARNING: the server's key has changed, so this may not be your server. "+
				"Stopping for safety. If the server was really reinstalled, remove its line from %s and run again.", t.knownHosts)
		}

		// The person may take a while to answer, so pause the handshake timeout.
		conn.SetDeadline(time.Time{})
		trusted, err := t.confirm(fmt.Sprintf("The server %s is not known yet.\nKey fingerprint: %s\nTrust it and remember it?",
			host, ssh.FingerprintSHA256(key)))
		conn.SetDeadline(time.Now().Add(t.dialTimeout))
		if err != nil {
			return fatalf("could not ask whether to trust the server: %v", err)
		}
		if !trusted {
			return fatalf("stopped because the server was not trusted.")
		}
		return appendKnownHost(t.knownHosts, host, key)
	}
}

// knownKeyAlgorithms asks only for key types we already hold for this host.
// Without it a server with several host keys can offer a type missing from
// known_hosts, which would look exactly like a changed key.
func knownKeyAlgorithms(check ssh.HostKeyCallback, addr string) []string {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(check(addr, &net.TCPAddr{IP: net.IPv4zero}, probe), &keyErr) {
		return nil
	}
	var algorithms []string
	for _, known := range keyErr.Want {
		if known.Key.Type() == ssh.KeyAlgoRSA {
			algorithms = append(algorithms, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
			continue
		}
		algorithms = append(algorithms, known.Key.Type())
	}
	return algorithms
}

func appendKnownHost(path, host string, key ssh.PublicKey) error {
	existing, err := os.ReadFile(path)
	if err != nil {
		return fatalf("cannot read %s: %v", path, err)
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(host)}, key) + "\n"
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		line = "\n" + line
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fatalf("cannot update %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fatalf("cannot update %s: %v", path, err)
	}
	return nil
}

// sshSession is a live SSH client with a keepalive that closes it when the
// server stops answering, which is how silent network loss gets noticed.
type sshSession struct {
	client *ssh.Client
	done   chan struct{}
}

func newSSHSession(client *ssh.Client, interval, timeout time.Duration) *sshSession {
	s := &sshSession{client: client, done: make(chan struct{})}
	go func() { client.Wait(); close(s.done) }()
	go s.keepalive(interval, timeout)
	return s
}

func (s *sshSession) keepalive(interval, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
		reply := make(chan error, 1)
		go func() {
			_, _, err := s.client.SendRequest("keepalive@openssh.com", true, nil)
			reply <- err
		}()
		select {
		case <-s.done:
			return
		case err := <-reply:
			if err != nil {
				s.client.Close()
				return
			}
		case <-time.After(timeout):
			s.client.Close()
			return
		}
	}
}

func (s *sshSession) Dial(network, addr string) (net.Conn, error) {
	return s.client.Dial(network, addr)
}

func (s *sshSession) Wait() error {
	<-s.done
	return nil
}

func (s *sshSession) Close() error { return s.client.Close() }

// loadSigner reads the private key, asking for its passphrase only if needed.
// The decrypted key lives in memory until the process exits.
func loadSigner(path string, prompt func(string) ([]byte, error)) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fatalf("cannot read your key file at %s: %v", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		if err != nil {
			return nil, fatalf("%s is not a usable private key: %v", path, err)
		}
		return signer, nil
	}

	passphrase, err := prompt(fmt.Sprintf("Passphrase for %s: ", filepath.Base(path)))
	if err != nil {
		return nil, fatalf("could not read the passphrase: %v", err)
	}
	defer clear(passphrase)
	signer, err = ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
	if errors.Is(err, x509.IncorrectPasswordError) {
		return nil, fatalf("wrong passphrase for %s. Run the command again.", path)
	}
	if err != nil {
		return nil, fatalf("%s is not a usable private key: %v", path, err)
	}
	return signer, nil
}
