package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestBackoffDelay(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, 16 * time.Second},
		{5, 30 * time.Second},
		{6, 30 * time.Second},
		{1000, 30 * time.Second},
	}
	for _, tt := range tests {
		if got := backoffDelay(tt.attempt); got != tt.want {
			t.Errorf("backoffDelay(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
}

func TestReason(t *testing.T) {
	wrap := func(e error) error { return &net.OpError{Op: "dial", Net: "tcp", Err: e} }
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"windows network unreachable", wrap(syscall.Errno(10051)), "network unreachable"},
		{"windows host unreachable", wrap(syscall.Errno(10065)), "network unreachable"},
		{"windows refused", wrap(syscall.Errno(10061)), "connection refused"},
		{"dns", wrap(&net.DNSError{Err: "no such host", Name: "x"}), "name lookup failed"},
		{"timeout", fmt.Errorf("dial: %w", context.DeadlineExceeded), "timed out"},
		{"other", errors.New("something odd"), "something odd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reason(tt.err); got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}
}

type fakeSession struct {
	died   chan struct{}
	dialed chan string
	once   sync.Once
	closed chan struct{}
}

func newFakeSession() *fakeSession {
	return &fakeSession{died: make(chan struct{}), dialed: make(chan string, 1), closed: make(chan struct{})}
}

func (f *fakeSession) Dial(network, addr string) (net.Conn, error) {
	f.dialed <- addr
	return nil, errors.New("fake")
}
func (f *fakeSession) Wait() error { <-f.died; return nil }
func (f *fakeSession) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}
func (f *fakeSession) kill() { close(f.died) }

// script drives a supervisor through a fixed list of connect results.
type script struct {
	mu     sync.Mutex
	steps  []func() (session, error)
	lines  []string
	sleeps []time.Duration
	calls  int
}

func (s *script) connect(ctx context.Context) (session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls >= len(s.steps) {
		return nil, &fatalError{msg: "script finished"}
	}
	step := s.steps[s.calls]
	s.calls++
	return step()
}

func (s *script) log(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, line)
}

func (s *script) sleep(ctx context.Context, d time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sleeps = append(s.sleeps, d)
	return true
}

func (s *script) output() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func (s *script) supervisor() *supervisor {
	return &supervisor{name: "green", connect: s.connect, log: s.log, sleep: s.sleep, minUptime: time.Minute}
}

func fail(msg string) func() (session, error) {
	return func() (session, error) { return nil, errors.New(msg) }
}

func up(f *fakeSession) func() (session, error) {
	return func() (session, error) { return f, nil }
}

func assertLines(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d lines %q, want %d lines %q", len(got), got, len(want), want)
	}
	for i := range want {
		if !strings.Contains(got[i], want[i]) {
			t.Fatalf("line %d = %q, want it to contain %q", i, got[i], want[i])
		}
	}
}

func TestSupervisorRetriesUntilConnected(t *testing.T) {
	f := newFakeSession()
	s := &script{steps: []func() (session, error){fail("no route"), fail("no route"), up(f)}}
	sup := s.supervisor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitFor(t, func() bool { return len(s.output()) == 3 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run after cancel: %v", err)
	}
	assertLines(t, s.output(),
		"retry 1 failed (no route), next in 2s",
		"retry 2 failed (no route), next in 4s, press Enter to retry now",
		"connected to green after 3 attempts",
	)
	if len(s.sleeps) != 2 || s.sleeps[0] != 2*time.Second || s.sleeps[1] != 4*time.Second {
		t.Fatalf("sleeps = %v, want [2s 4s]", s.sleeps)
	}
}

func TestSupervisorReconnectsAfterLoss(t *testing.T) {
	first, second := newFakeSession(), newFakeSession()
	s := &script{steps: []func() (session, error){up(first), up(second)}}
	sup := s.supervisor()
	sup.minUptime = 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitFor(t, func() bool { return len(s.output()) == 1 })
	first.kill()
	waitFor(t, func() bool { return len(s.output()) == 3 })
	cancel()
	<-done

	assertLines(t, s.output(), "connected to green", "connection lost", "connected to green")
	select {
	case <-first.closed:
	default:
		t.Fatal("dead session was not closed")
	}
}

func TestSupervisorResetsRetryCountAfterSuccess(t *testing.T) {
	first, second := newFakeSession(), newFakeSession()
	s := &script{steps: []func() (session, error){fail("x"), up(first), fail("y"), up(second)}}
	sup := s.supervisor()
	sup.minUptime = 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitFor(t, func() bool { return len(s.output()) == 2 })
	first.kill()
	waitFor(t, func() bool { return len(s.output()) == 5 })
	cancel()
	<-done
	assertLines(t, s.output(),
		"retry 1 failed (x)",
		"connected to green after 2 attempts",
		"connection lost",
		"retry 1 failed (y), next in 2s",
		"connected to green after 2 attempts",
	)
}

func TestSupervisorStopsOnFatalError(t *testing.T) {
	s := &script{steps: []func() (session, error){func() (session, error) {
		return nil, &fatalError{msg: "server key changed"}
	}}}
	err := s.supervisor().Run(context.Background())
	var fatal *fatalError
	if !errors.As(err, &fatal) || fatal.msg != "server key changed" {
		t.Fatalf("err = %v, want the fatal error", err)
	}
	if s.calls != 1 {
		t.Fatalf("connect called %d times, want 1", s.calls)
	}
}

func TestSupervisorPausesWhenSessionDiesQuickly(t *testing.T) {
	first, second := newFakeSession(), newFakeSession()
	first.kill()
	s := &script{steps: []func() (session, error){up(first), up(second)}}
	sup := s.supervisor() // minUptime of a minute: the session below lives far less
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()
	waitFor(t, func() bool { return len(s.output()) == 3 })
	cancel()
	<-done
	if len(s.sleeps) != 1 || s.sleeps[0] != 2*time.Second {
		t.Fatalf("sleeps = %v, want one 2s pause", s.sleeps)
	}
}

func TestSupervisorDialUsesCurrentSession(t *testing.T) {
	f := newFakeSession()
	s := &script{steps: []func() (session, error){up(f)}}
	sup := s.supervisor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()
	waitFor(t, func() bool { return len(s.output()) == 1 })

	sup.Dial("tcp", "example.com:80")
	select {
	case got := <-f.dialed:
		if got != "example.com:80" {
			t.Fatalf("dialed %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("session was not dialed")
	}
	cancel()
	<-done
}

func TestSupervisorDialFailsWhileDisconnected(t *testing.T) {
	sup := &supervisor{}
	if _, err := sup.Dial("tcp", "example.com:80"); err == nil {
		t.Fatal("expected an error with no session")
	}
}

func TestSupervisorDoesNotCallCancelAnError(t *testing.T) {
	f := newFakeSession()
	s := &script{steps: []func() (session, error){up(f)}}
	ctx, cancel := context.WithCancel(context.Background())
	sup := s.supervisor()
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()
	waitFor(t, func() bool { return len(s.output()) == 1 })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
	for _, line := range s.output() {
		if strings.Contains(line, "connection lost") {
			t.Fatalf("stopping should not report a lost connection: %q", line)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
