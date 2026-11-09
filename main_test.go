package main

import (
	"strings"
	"testing"
)

func TestParseStartArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"default port", []string{"start"}, 1080},
		{"custom port", []string{"start", "--port", "9050"}, 9050},
		{"equals form", []string{"start", "--port=9050"}, 9050},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseStartArgs(tt.args)
			if err != nil {
				t.Fatalf("parseStartArgs: %v", err)
			}
			if got != tt.want {
				t.Fatalf("port = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseStartArgsRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no command", nil},
		{"unknown command", []string{"stop"}},
		{"port zero", []string{"start", "--port", "0"}},
		{"port too large", []string{"start", "--port", "70000"}},
		{"port not a number", []string{"start", "--port", "abc"}},
		{"stray argument", []string{"start", "extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseStartArgs(tt.args)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), "green start") {
				t.Fatalf("error should show how to use the tool: %v", err)
			}
		})
	}
}
