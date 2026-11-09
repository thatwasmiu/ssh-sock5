package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

const maxBackoff = 30 * time.Second

// session is one live connection to the server.
type session interface {
	Dial(network, addr string) (net.Conn, error)
	Wait() error // blocks until the connection is dead
	Close() error
}

// supervisor keeps a session up, reconnecting whenever it is lost.
type supervisor struct {
	name      string
	connect   func(context.Context) (session, error)
	log       func(string)
	sleep     func(context.Context, time.Duration) bool
	minUptime time.Duration // a session shorter than this pauses before reconnecting

	mu      sync.RWMutex
	current session
}

// Run returns nil once ctx is cancelled, or the fatal error that stopped it.
func (s *supervisor) Run(ctx context.Context) error {
	failures := 0
	for {
		sess, err := s.connect(ctx)
		if ctx.Err() != nil {
			if sess != nil {
				sess.Close()
			}
			return nil
		}
		if err != nil {
			var fatal *fatalError
			if errors.As(err, &fatal) {
				return err
			}
			failures++
			delay := backoffDelay(failures)
			s.log(fmt.Sprintf("retry %d failed (%s), next in %s", failures, reason(err), delay))
			if !s.sleep(ctx, delay) {
				return nil
			}
			continue
		}

		s.setCurrent(sess)
		started := time.Now()
		if failures > 0 {
			s.log(fmt.Sprintf("connected to %s after %d attempts", s.name, failures+1))
		} else {
			s.log("connected to " + s.name)
		}
		failures = 0

		died := make(chan struct{})
		go func() { sess.Wait(); close(died) }()
		select {
		case <-ctx.Done():
			s.setCurrent(nil)
			sess.Close()
			return nil
		case <-died:
		}
		s.setCurrent(nil)
		sess.Close()
		s.log("connection lost")

		// A server that accepts and instantly drops us must not cause a tight loop.
		if time.Since(started) < s.minUptime && !s.sleep(ctx, backoffDelay(1)) {
			return nil
		}
	}
}

// Dial opens a connection through the tunnel, failing fast while it is down.
func (s *supervisor) Dial(network, addr string) (net.Conn, error) {
	s.mu.RLock()
	sess := s.current
	s.mu.RUnlock()
	if sess == nil {
		return nil, errors.New("tunnel is down")
	}
	return sess.Dial(network, addr)
}

func (s *supervisor) setCurrent(sess session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = sess
}

func backoffDelay(attempt int) time.Duration {
	delay := 2 * time.Second
	for i := 1; i < attempt && delay < maxBackoff; i++ {
		delay *= 2
	}
	return min(delay, maxBackoff)
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// reason turns a connection error into a few plain words.
func reason(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "name lookup failed"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch {
		case errno == 10051, errno == 10065, errno == syscall.ENETUNREACH, errno == syscall.EHOSTUNREACH:
			return "network unreachable"
		case errno == 10061, errno == syscall.ECONNREFUSED:
			return "connection refused"
		case errno == 10060:
			return "timed out"
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timed out"
	}
	return err.Error()
}
