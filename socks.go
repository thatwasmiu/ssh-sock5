package main

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	socksVersion   = 5
	socksNoAuth    = 0
	socksNoMethods = 0xFF

	socksCmdConnect = 1

	socksAddrIPv4   = 1
	socksAddrDomain = 3
	socksAddrIPv6   = 4

	socksOK             = 0
	socksFailure        = 1
	socksBadCommand     = 7
	socksBadAddressType = 8

	socksHandshakeTimeout = 30 * time.Second
)

type dialFunc func(network, addr string) (net.Conn, error)

// serveSOCKS answers SOCKS5 CONNECT requests until ln is closed.
func serveSOCKS(ln net.Listener, dial dialFunc) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSOCKS(conn, dial)
	}
}

func handleSOCKS(client net.Conn, dial dialFunc) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(socksHandshakeTimeout))

	if !socksGreet(client) {
		return
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != socksVersion {
		return
	}
	if head[1] != socksCmdConnect {
		socksReply(client, socksBadCommand)
		return
	}
	addr, code := socksReadAddr(client, head[3])
	if code != socksOK {
		socksReply(client, code)
		return
	}

	remote, err := dial("tcp", addr)
	if err != nil {
		socksReply(client, socksFailure)
		return
	}
	defer remote.Close()
	if socksReply(client, socksOK) != nil {
		return
	}
	client.SetDeadline(time.Time{})
	relay(client, remote)
}

func socksGreet(client net.Conn) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != socksVersion {
		return false
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return false
	}
	for _, m := range methods {
		if m == socksNoAuth {
			_, err := client.Write([]byte{socksVersion, socksNoAuth})
			return err == nil
		}
	}
	client.Write([]byte{socksVersion, socksNoMethods})
	return false
}

func socksReadAddr(client net.Conn, addrType byte) (string, byte) {
	var host string
	switch addrType {
	case socksAddrIPv4, socksAddrIPv6:
		size := net.IPv4len
		if addrType == socksAddrIPv6 {
			size = net.IPv6len
		}
		ip := make(net.IP, size)
		if _, err := io.ReadFull(client, ip); err != nil {
			return "", socksFailure
		}
		host = ip.String()
	case socksAddrDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(client, length); err != nil {
			return "", socksFailure
		}
		name := make([]byte, length[0])
		if _, err := io.ReadFull(client, name); err != nil {
			return "", socksFailure
		}
		host = string(name)
	default:
		return "", socksBadAddressType
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(client, port); err != nil {
		return "", socksFailure
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), socksOK
}

func socksReply(client net.Conn, code byte) error {
	_, err := client.Write([]byte{socksVersion, code, 0, socksAddrIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if w, ok := dst.(interface{ CloseWrite() error }); ok {
			w.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go copyHalf(a, b)
	go copyHalf(b, a)
	wg.Wait()
}
