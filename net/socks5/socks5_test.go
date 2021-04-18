// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package socks5 is a SOCKS5 server implementation
// for userspace networking in Tailscale.
package socks5

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"golang.org/x/net/proxy"
)

var backendServerPort int
var socks5Port int

func socks5Server(listener net.Listener) {
	var server Server
	err := server.Serve(listener)
	if err != nil {
		panic(err)
	}
}

func backendServer(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		conn.Write([]byte("Test"))
		conn.Close()
	}
}

func TestRead(t *testing.T) {
	addr := fmt.Sprintf("localhost:%d", socks5Port)
	socksDialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	addr = fmt.Sprintf("localhost:%d", backendServerPort)
	conn, err := socksDialer.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != "Test" {
		t.Fatalf("got: %s want: Test", string(buf))
	}

	err = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestMain(m *testing.M) {
	// backend server which we'll use SOCKS5 to connect to
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	backendServerPort = listener.Addr().(*net.TCPAddr).Port
	go backendServer(listener)

	// SOCKS5 server
	listener, err = net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	socks5Port = listener.Addr().(*net.TCPAddr).Port
	go socks5Server(listener)

	os.Exit(m.Run())
}
