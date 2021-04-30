// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wgcfg has types and a parser for representing WireGuard config.
package wgcfg

import (
	"strings"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

//go:generate go run tailscale.com/cmd/cloner -type=Config,Peer,Endpoints -output=clone.go

// Config is a WireGuard configuration.
// It only supports the set of things Tailscale uses.
type Config struct {
	Name       string
	PrivateKey wgkey.Private
	Addresses  []netaddr.IPPrefix
	MTU        uint16
	DNS        []netaddr.IP
	Peers      []Peer
}

type Peer struct {
	PublicKey           wgkey.Key
	AllowedIPs          []netaddr.IPPrefix
	Endpoints           Endpoints
	PersistentKeepalive uint16
}

// Endpoints represents the routes to reach a remote node.
// It is serialized and provided to wireguard-go as a conn.Endpoint.
type Endpoints struct {
	// PublicKey is the public key for the remote node.
	PublicKey wgkey.Key `json:"pk"`
	// DiscoKey is the disco key associated with the remote node.
	DiscoKey tailcfg.DiscoKey `json:"dk,omitempty"`
	// IPPorts is a set of possible ip+ports the remote node can be reached at.
	IPPorts []netaddr.IPPort `json:"ipp,omitempty"`
}

func (e Endpoints) Equal(f Endpoints) bool {
	if e.PublicKey != f.PublicKey {
		return false
	}
	if e.DiscoKey != f.DiscoKey {
		return false
	}
	if len(e.IPPorts) != len(f.IPPorts) {
		return false
	}
	// Check whether the endpoints are the same, regardless of order.
	ipps := make(map[netaddr.IPPort]int, len(e.IPPorts))
	for _, ipp := range e.IPPorts {
		ipps[ipp]++
	}
	for _, ipp := range f.IPPorts {
		ipps[ipp]--
	}
	for _, n := range ipps {
		if n != 0 {
			return false
		}
	}
	return true
}

// IPPortsString returns a comma-separated list of all IPPorts in e.IPPorts.
func (e Endpoints) IPPortsString() string {
	buf := new(strings.Builder)
	for i, ipp := range e.IPPorts {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(ipp.String())
	}
	return buf.String()
}

// PeerWithKey returns the Peer with key k and reports whether it was found.
func (config Config) PeerWithKey(k wgkey.Key) (Peer, bool) {
	for _, p := range config.Peers {
		if p.PublicKey == k {
			return p, true
		}
	}
	return Peer{}, false
}
