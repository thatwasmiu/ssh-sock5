package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// keyboard is the only reader of standard input after the passphrase prompt,
// so the retry wait and the trust question never compete for the same line.
type keyboard struct{ lines chan string }

func newKeyboard(r io.Reader) *keyboard {
	k := &keyboard{lines: make(chan string, 16)}
	go k.pump(r)
	return k
}

func (k *keyboard) pump(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		select {
		case k.lines <- scanner.Text():
		default: // nobody is reading and the buffer is full, so drop it
		}
	}
	close(k.lines)
}

// discard drops key presses made so far.
func (k *keyboard) discard() {
	for {
		select {
		case _, ok := <-k.lines:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

// sleep waits for d or until Enter is pressed, counting presses made since the
// last discard. It returns false only if ctx is cancelled.
func (k *keyboard) sleep(ctx context.Context, d time.Duration) bool {
	lines := k.lines
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return true
		case <-ctx.Done():
			return false
		case _, ok := <-lines:
			if ok {
				return true
			}
			lines = nil // input closed: nothing can wake us, so wait out the timer
		}
	}
}

// confirm asks a yes/no question, where anything but yes means no.
func (k *keyboard) confirm(prompt string) (bool, error) {
	fmt.Printf("%s [y/N]: ", prompt)
	answer, err := k.readAnswer()
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

func (k *keyboard) readAnswer() (string, error) {
	// Enter presses from before the question appeared are not answers.
	for {
		select {
		case line, ok := <-k.lines:
			if !ok {
				return "", io.EOF
			}
			if strings.TrimSpace(line) != "" {
				return line, nil
			}
			continue
		default:
		}
		line, ok := <-k.lines
		if !ok {
			return "", io.EOF
		}
		return line, nil
	}
}
