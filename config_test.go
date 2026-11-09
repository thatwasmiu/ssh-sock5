package main

import (
	"errors"
	"strings"
	"testing"
)

func TestParseHost(t *testing.T) {
	const home = `C:\Users\me`
	tests := []struct {
		name   string
		config string
		want   hostConfig
	}{
		{
			name: "plain block with default port",
			config: "Host green\n    HostName 203.0.113.10\n    User root\n" +
				"    IdentityFile C:\\Users\\me\\.ssh\\my_key\n",
			want: hostConfig{HostName: "203.0.113.10", Port: 22, User: "root", IdentityFile: `C:\Users\me\.ssh\my_key`},
		},
		{
			name:   "tilde expands to home",
			config: "Host green\n HostName h\n User u\n IdentityFile ~/.ssh/key\n",
			want:   hostConfig{HostName: "h", Port: 22, User: "u", IdentityFile: home + `/.ssh/key`},
		},
		{
			name:   "hostname defaults to the alias",
			config: "Host green\n User u\n IdentityFile /k\n",
			want:   hostConfig{HostName: "green", Port: 22, User: "u", IdentityFile: "/k"},
		},
		{
			name:   "first value wins over a later wildcard",
			config: "Host green\n HostName h\n User u\n IdentityFile /k\nHost *\n User other\n Port 2222\n",
			want:   hostConfig{HostName: "h", Port: 2222, User: "u", IdentityFile: "/k"},
		},
		{
			name:   "other hosts are ignored",
			config: "Host blue\n HostName wrong\n User wrong\nHost green\n HostName h\n User u\n IdentityFile /k\n",
			want:   hostConfig{HostName: "h", Port: 22, User: "u", IdentityFile: "/k"},
		},
		{
			name:   "comments, equals, case and quotes",
			config: "# top\nHOST green\n  hostname=h\n  USER u # not parsed as value\n  identityfile \"/my keys/k\"\n",
			want:   hostConfig{HostName: "h", Port: 22, User: "u", IdentityFile: "/my keys/k"},
		},
		{
			name:   "one of several patterns matches",
			config: "Host blue gre* \n HostName h\n User u\n IdentityFile /k\n",
			want:   hostConfig{HostName: "h", Port: 22, User: "u", IdentityFile: "/k"},
		},
		{
			name:   "negated pattern excludes the block",
			config: "Host * !green\n User wrong\nHost green\n HostName h\n User u\n IdentityFile /k\n",
			want:   hostConfig{HostName: "h", Port: 22, User: "u", IdentityFile: "/k"},
		},
		{
			name:   "match blocks are skipped",
			config: "Match all\n User wrong\nHost green\n HostName h\n User u\n IdentityFile /k\n",
			want:   hostConfig{HostName: "h", Port: 22, User: "u", IdentityFile: "/k"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHost(strings.NewReader(tt.config), "green", home)
			if err != nil {
				t.Fatalf("parseHost: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseHostErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantMsg string
	}{
		{"host missing", "Host blue\n User u\n", "green"},
		{"no user", "Host green\n HostName h\n IdentityFile /k\n", "User"},
		{"no key", "Host green\n HostName h\n User u\n", "IdentityFile"},
		{"bad port", "Host green\n User u\n IdentityFile /k\n Port abc\n", "Port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseHost(strings.NewReader(tt.config), "green", "/home")
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error %q should mention %q", err, tt.wantMsg)
			}
			var fatal *fatalError
			if !errors.As(err, &fatal) {
				t.Fatalf("config errors must be fatal, got %T", err)
			}
		})
	}
}
