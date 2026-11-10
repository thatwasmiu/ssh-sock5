// Command green keeps an SSH SOCKS5 tunnel to the "green" host alive,
// reconnecting on its own whenever the network drops.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/term"
)

const (
	hostAlias   = "green"
	defaultPort = 1080
	usage       = "usage: green start [--port N]"

	dialTimeout  = 15 * time.Second
	pingInterval = 10 * time.Second
	pingTimeout  = 15 * time.Second
	minUptime    = 10 * time.Second

	stopGrace = 2 * time.Second
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseStartArgs(args []string) (int, error) {
	if len(args) == 0 || args[0] != "start" {
		return 0, errors.New(usage)
	}
	flags := flag.NewFlagSet("start", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	port := flags.Int("port", defaultPort, "")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return 0, errors.New(usage)
	}
	if *port < 1 || *port > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535. %s", usage)
	}
	return *port, nil
}

func run(args []string) error {
	port, err := parseStartArgs(args)
	if err != nil {
		return err
	}
	host, home, err := loadHost(hostAlias)
	if err != nil {
		return err
	}
	signer, err := loadSigner(host.IdentityFile, readPassphrase)
	if err != nil {
		return err
	}

	listenAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fatalf("cannot open port %d, another program may be using it. Try --port with a different number.", port)
	}
	defer listener.Close()
	fmt.Printf("SOCKS5 proxy on %s\n", listenAddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	keys := newKeyboard(os.Stdin)
	tgt := &target{
		addr:         net.JoinHostPort(host.HostName, strconv.Itoa(host.Port)),
		user:         host.User,
		signer:       signer,
		knownHosts:   filepath.Join(home, ".ssh", "known_hosts"),
		dialTimeout:  dialTimeout,
		pingInterval: pingInterval,
		pingTimeout:  pingTimeout,
		confirm:      keys.confirm,
	}
	sup := &supervisor{
		name:      hostAlias,
		connect:   tgt.connect,
		log:       logLine,
		sleep:     keys.sleep,
		minUptime: minUptime,

		discardKeys: keys.discard,
	}
	go serveSOCKS(listener, sup.Dial)

	finished := make(chan error, 1)
	go func() { finished <- sup.Run(ctx) }()

	select {
	case err = <-finished:
	case <-ctx.Done():
		// Run may be blocked on a keyboard prompt, so don't wait on it forever.
		select {
		case err = <-finished:
		case <-time.After(stopGrace):
		}
	}
	if err != nil {
		return err
	}
	logLine("stopped")
	return nil
}

func logLine(line string) {
	fmt.Printf("%s  %s\n", time.Now().Format("15:04:05"), line)
}

func readPassphrase(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("run green from a terminal so it can ask for the passphrase")
	}
	fmt.Print(prompt)
	defer fmt.Println()
	return term.ReadPassword(fd)
}
