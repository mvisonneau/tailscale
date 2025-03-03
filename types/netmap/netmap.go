// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netmap contains the netmap.NetworkMap type.
package netmap

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
	"tailscale.com/wgengine/filter"
)

// NetworkMap is the current state of the world.
//
// The fields should all be considered read-only. They might
// alias parts of previous NetworkMap values.
type NetworkMap struct {
	// Core networking

	SelfNode   *tailcfg.Node
	NodeKey    tailcfg.NodeKey
	PrivateKey wgkey.Private
	Expiry     time.Time
	// Name is the DNS name assigned to this node.
	Name          string
	Addresses     []netaddr.IPPrefix
	LocalPort     uint16 // used for debugging
	MachineStatus tailcfg.MachineStatus
	MachineKey    tailcfg.MachineKey
	Peers         []*tailcfg.Node // sorted by Node.ID
	DNS           tailcfg.DNSConfig
	Hostinfo      tailcfg.Hostinfo
	PacketFilter  []filter.Match

	// CollectServices reports whether this node's Tailnet has
	// requested that info about services be included in HostInfo.
	// If set, Hostinfo.ShieldsUp blocks services collection; that
	// takes precedence over this field.
	CollectServices bool

	// DERPMap is the last DERP server map received. It's reused
	// between updates and should not be modified.
	DERPMap *tailcfg.DERPMap

	// Debug knobs from control server for debug or feature gating.
	Debug *tailcfg.Debug

	// ACLs

	User   tailcfg.UserID
	Domain string

	UserProfiles map[tailcfg.UserID]tailcfg.UserProfile
}

// MagicDNSSuffix returns the domain's MagicDNS suffix (even if
// MagicDNS isn't necessarily in use).
//
// It will neither start nor end with a period.
func (nm *NetworkMap) MagicDNSSuffix() string {
	name := strings.Trim(nm.Name, ".")
	if i := strings.Index(name, "."); i != -1 {
		name = name[i+1:]
	}
	return name
}

func (nm *NetworkMap) String() string {
	return nm.Concise()
}

func (nm *NetworkMap) Concise() string {
	buf := new(strings.Builder)

	nm.printConciseHeader(buf)
	for _, p := range nm.Peers {
		printPeerConcise(buf, p)
	}
	return buf.String()
}

// printConciseHeader prints a concise header line representing nm to buf.
//
// If this function is changed to access different fields of nm, keep
// in equalConciseHeader in sync.
func (nm *NetworkMap) printConciseHeader(buf *strings.Builder) {
	fmt.Fprintf(buf, "netmap: self: %v auth=%v",
		nm.NodeKey.ShortString(), nm.MachineStatus)
	login := nm.UserProfiles[nm.User].LoginName
	if login == "" {
		if nm.User.IsZero() {
			login = "?"
		} else {
			login = fmt.Sprint(nm.User)
		}
	}
	fmt.Fprintf(buf, " u=%s", login)
	if nm.LocalPort != 0 {
		fmt.Fprintf(buf, " port=%v", nm.LocalPort)
	}
	if nm.Debug != nil {
		j, _ := json.Marshal(nm.Debug)
		fmt.Fprintf(buf, " debug=%s", j)
	}
	fmt.Fprintf(buf, " %v", nm.Addresses)
	buf.WriteByte('\n')
}

// equalConciseHeader reports whether a and b are equal for the fields
// used by printConciseHeader.
func (a *NetworkMap) equalConciseHeader(b *NetworkMap) bool {
	if a.NodeKey != b.NodeKey ||
		a.MachineStatus != b.MachineStatus ||
		a.LocalPort != b.LocalPort ||
		a.User != b.User ||
		len(a.Addresses) != len(b.Addresses) {
		return false
	}
	for i, a := range a.Addresses {
		if b.Addresses[i] != a {
			return false
		}
	}
	return (a.Debug == nil && b.Debug == nil) || reflect.DeepEqual(a.Debug, b.Debug)
}

// printPeerConcise appends to buf a line repsenting the peer p.
//
// If this function is changed to access different fields of p, keep
// in nodeConciseEqual in sync.
func printPeerConcise(buf *strings.Builder, p *tailcfg.Node) {
	aip := make([]string, len(p.AllowedIPs))
	for i, a := range p.AllowedIPs {
		s := strings.TrimSuffix(fmt.Sprint(a), "/32")
		aip[i] = s
	}

	ep := make([]string, len(p.Endpoints))
	for i, e := range p.Endpoints {
		// Align vertically on the ':' between IP and port
		colon := strings.IndexByte(e, ':')
		spaces := 0
		for colon > 0 && len(e)+spaces-colon < 6 {
			spaces++
			colon--
		}
		ep[i] = fmt.Sprintf("%21v", e+strings.Repeat(" ", spaces))
	}

	derp := p.DERP
	const derpPrefix = "127.3.3.40:"
	if strings.HasPrefix(derp, derpPrefix) {
		derp = "D" + derp[len(derpPrefix):]
	}
	var discoShort string
	if !p.DiscoKey.IsZero() {
		discoShort = p.DiscoKey.ShortString() + " "
	}

	// Most of the time, aip is just one element, so format the
	// table to look good in that case. This will also make multi-
	// subnet nodes stand out visually.
	fmt.Fprintf(buf, " %v %s%-2v %-15v : %v\n",
		p.Key.ShortString(),
		discoShort,
		derp,
		strings.Join(aip, " "),
		strings.Join(ep, " "))
}

// nodeConciseEqual reports whether a and b are equal for the fields accessed by printPeerConcise.
func nodeConciseEqual(a, b *tailcfg.Node) bool {
	return a.Key == b.Key &&
		a.DERP == b.DERP &&
		a.DiscoKey == b.DiscoKey &&
		eqCIDRsIgnoreNil(a.AllowedIPs, b.AllowedIPs) &&
		eqStringsIgnoreNil(a.Endpoints, b.Endpoints)
}

func (b *NetworkMap) ConciseDiffFrom(a *NetworkMap) string {
	var diff strings.Builder

	// See if header (non-peers, "bare") part of the network map changed.
	// If so, print its diff lines first.
	if !a.equalConciseHeader(b) {
		diff.WriteByte('-')
		a.printConciseHeader(&diff)
		diff.WriteByte('+')
		b.printConciseHeader(&diff)
	}

	aps, bps := a.Peers, b.Peers
	for len(aps) > 0 && len(bps) > 0 {
		pa, pb := aps[0], bps[0]
		switch {
		case pa.ID == pb.ID:
			if !nodeConciseEqual(pa, pb) {
				diff.WriteByte('-')
				printPeerConcise(&diff, pa)
				diff.WriteByte('+')
				printPeerConcise(&diff, pb)
			}
			aps, bps = aps[1:], bps[1:]
		case pa.ID > pb.ID:
			// New peer in b.
			diff.WriteByte('+')
			printPeerConcise(&diff, pb)
			bps = bps[1:]
		case pb.ID > pa.ID:
			// Deleted peer in b.
			diff.WriteByte('-')
			printPeerConcise(&diff, pa)
			aps = aps[1:]
		}
	}
	for _, pa := range aps {
		diff.WriteByte('-')
		printPeerConcise(&diff, pa)
	}
	for _, pb := range bps {
		diff.WriteByte('+')
		printPeerConcise(&diff, pb)
	}
	return diff.String()
}

func (nm *NetworkMap) JSON() string {
	b, err := json.MarshalIndent(*nm, "", "  ")
	if err != nil {
		return fmt.Sprintf("[json error: %v]", err)
	}
	return string(b)
}

// WGConfigFlags is a bitmask of flags to control the behavior of the
// wireguard configuration generation done by NetMap.WGCfg.
type WGConfigFlags int

const (
	AllowSingleHosts WGConfigFlags = 1 << iota
	AllowSubnetRoutes
)

// eqStringsIgnoreNil reports whether a and b have the same length and
// contents, but ignore whether a or b are nil.
func eqStringsIgnoreNil(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// eqCIDRsIgnoreNil reports whether a and b have the same length and
// contents, but ignore whether a or b are nil.
func eqCIDRsIgnoreNil(a, b []netaddr.IPPrefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
