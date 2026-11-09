package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// fatalError is a problem retrying cannot fix, so the tool stops and says why.
type fatalError struct{ msg string }

func (e *fatalError) Error() string { return e.msg }

func fatalf(format string, a ...any) error {
	return &fatalError{msg: fmt.Sprintf(format, a...)}
}

type hostConfig struct {
	HostName     string
	Port         int
	User         string
	IdentityFile string
}

// loadHost reads alias from ~/.ssh/config.
func loadHost(alias string) (hostConfig, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return hostConfig{}, "", fatalf("cannot find your home folder: %v", err)
	}
	configPath := filepath.Join(home, ".ssh", "config")
	f, err := os.Open(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return hostConfig{}, "", fatalf("SSH config not found at %s. Create it with a \"Host %s\" entry.", configPath, alias)
	}
	if err != nil {
		return hostConfig{}, "", fatalf("cannot read %s: %v", configPath, err)
	}
	defer f.Close()
	cfg, err := parseHost(f, alias, home)
	return cfg, home, err
}

// parseHost applies OpenSSH's rule: the first value found for a keyword wins.
func parseHost(r io.Reader, alias, home string) (hostConfig, error) {
	values := map[string]string{}
	active, found := true, false

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cut := strings.IndexAny(line, " \t=")
		if cut < 0 {
			continue
		}
		key := strings.ToLower(line[:cut])
		rest := strings.TrimLeft(line[cut:], " \t=")

		switch key {
		case "host":
			active = hostMatches(strings.Fields(rest), alias)
			found = found || active
			continue
		case "match":
			active = false
			continue
		}
		if _, seen := values[key]; active && !seen {
			values[key] = firstToken(rest)
		}
	}
	if err := scanner.Err(); err != nil {
		return hostConfig{}, fatalf("cannot read SSH config: %v", err)
	}

	if !found {
		return hostConfig{}, fatalf("no \"Host %s\" entry in your SSH config.", alias)
	}
	cfg := hostConfig{HostName: values["hostname"], Port: 22, User: values["user"], IdentityFile: values["identityfile"]}
	if cfg.HostName == "" {
		cfg.HostName = alias
	}
	if cfg.User == "" {
		return hostConfig{}, fatalf("\"Host %s\" in your SSH config has no User line.", alias)
	}
	if cfg.IdentityFile == "" {
		return hostConfig{}, fatalf("\"Host %s\" in your SSH config has no IdentityFile line.", alias)
	}
	if strings.HasPrefix(cfg.IdentityFile, "~/") || strings.HasPrefix(cfg.IdentityFile, `~\`) {
		cfg.IdentityFile = home + cfg.IdentityFile[1:]
	}
	if p, ok := values["port"]; ok {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return hostConfig{}, fatalf("\"Host %s\" in your SSH config has an invalid Port: %q.", alias, p)
		}
		cfg.Port = n
	}
	return cfg, nil
}

func hostMatches(patterns []string, alias string) bool {
	alias = strings.ToLower(alias)
	matched := false
	for _, p := range patterns {
		negated := strings.HasPrefix(p, "!")
		ok, err := path.Match(strings.ToLower(strings.TrimPrefix(p, "!")), alias)
		if err != nil || !ok {
			continue
		}
		if negated {
			return false
		}
		matched = true
	}
	return matched
}

func firstToken(s string) string {
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			return s[1 : end+1]
		}
	}
	if end := strings.IndexAny(s, " \t"); end >= 0 {
		return s[:end]
	}
	return s
}
