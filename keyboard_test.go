package main

import (
	"context"
	"io"
	"testing"
	"time"
)

func newTestKeyboard(t *testing.T) (*keyboard, *io.PipeWriter) {
	t.Helper()
	r, w := io.Pipe()
	t.Cleanup(func() { w.Close() })
	return newKeyboard(r), w
}

func pressEnterAndWaitForBuffer(t *testing.T, k *keyboard, w io.Writer) {
	t.Helper()
	if _, err := io.WriteString(w, "\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(k.lines) == 1 })
}

func TestSleepEndsEarlyOnEnter(t *testing.T) {
	k, w := newTestKeyboard(t)
	done := make(chan bool, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		done <- k.sleep(context.Background(), time.Hour)
	}()
	<-started
	time.Sleep(20 * time.Millisecond) // let the wait begin, so Enter counts
	io.WriteString(w, "\n")

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("sleep = false, want true so the retry happens")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Enter did not end the wait")
	}
}

func TestSleepRunsFullDurationWithoutInput(t *testing.T) {
	k, _ := newTestKeyboard(t)
	start := time.Now()
	if !k.sleep(context.Background(), 80*time.Millisecond) {
		t.Fatal("sleep = false, want true")
	}
	if elapsed := time.Since(start); elapsed < 70*time.Millisecond {
		t.Fatalf("returned after %v, want the full wait", elapsed)
	}
}

func TestSleepIgnoresEnterPressedBeforeTheWait(t *testing.T) {
	k, w := newTestKeyboard(t)
	pressEnterAndWaitForBuffer(t, k, w)

	start := time.Now()
	k.sleep(context.Background(), 150*time.Millisecond)
	if elapsed := time.Since(start); elapsed < 130*time.Millisecond {
		t.Fatalf("an old key press cut the wait to %v", elapsed)
	}
}

func TestSleepReturnsFalseOnCancel(t *testing.T) {
	k, _ := newTestKeyboard(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if k.sleep(ctx, time.Hour) {
		t.Fatal("sleep = true, want false after cancel")
	}
}

func TestSleepIsNotWokenByClosedInput(t *testing.T) {
	k, w := newTestKeyboard(t)
	w.Close()
	waitFor(t, func() bool {
		select {
		case _, ok := <-k.lines:
			return !ok
		default:
			return false
		}
	})
	start := time.Now()
	k.sleep(context.Background(), 100*time.Millisecond)
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Fatalf("closed input ended the wait after %v", elapsed)
	}
}

func TestConfirmAnswers(t *testing.T) {
	tests := []struct {
		answer string
		want   bool
	}{
		{"y\n", true},
		{"YES\n", true},
		{"n\n", false},
		{"maybe\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.answer, func(t *testing.T) {
			k, w := newTestKeyboard(t)
			go io.WriteString(w, tt.answer)
			got, err := k.confirm("Trust?")
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("confirm = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfirmBlankAnswerMeansNo(t *testing.T) {
	k, w := newTestKeyboard(t)
	result := make(chan bool, 1)
	go func() {
		got, _ := k.confirm("Trust?")
		result <- got
	}()
	time.Sleep(20 * time.Millisecond) // Enter after the question is the default answer
	io.WriteString(w, "\n")
	select {
	case got := <-result:
		if got {
			t.Fatal("a blank answer must not trust the server")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("confirm did not return")
	}
}

func TestConfirmIgnoresEnterPressedBeforeTheQuestion(t *testing.T) {
	k, w := newTestKeyboard(t)
	pressEnterAndWaitForBuffer(t, k, w)

	result := make(chan bool, 1)
	go func() {
		got, _ := k.confirm("Trust?")
		result <- got
	}()
	select {
	case <-result:
		t.Fatal("an old key press answered the question")
	case <-time.After(60 * time.Millisecond):
	}
	io.WriteString(w, "y\n")
	if !<-result {
		t.Fatal("confirm = false, want the real answer")
	}
}

func TestConfirmFailsWhenInputCloses(t *testing.T) {
	k, w := newTestKeyboard(t)
	w.Close()
	if _, err := k.confirm("Trust?"); err == nil {
		t.Fatal("expected an error when no answer can arrive")
	}
}
