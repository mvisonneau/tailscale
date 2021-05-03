// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package nmcfg converts a controlclient.NetMap into a wgcfg config.
package nmcfg

import (
	"bytes"
	"fmt"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/wgkey"
	"tailscale.com/wgengine/wgcfg"
)

func nodeDebugName(n *tailcfg.Node) string {
	name := n.Name
	if name == "" {
		name = n.Hostinfo.Hostname
	}
	if i := strings.Index(name, "."); i != -1 {
		name = name[:i]
	}
	if name == "" && len(n.Addresses) != 0 {
		return n.Addresses[0].String()
	}
	return name
}

// cidrIsSubnet reports whether cidr is a non-default-route subnet
// exported by node that is not one of its own self addresses.
func cidrIsSubnet(node *tailcfg.Node, cidr netaddr.IPPrefix) bool {
	if cidr.Bits == 0 {
		return false
	}
	if !cidr.IsSingleIP() {
		return true
	}
	for _, selfCIDR := range node.Addresses {
		if cidr == selfCIDR {
			return false
		}
	}
	return true
}

// WGCfg returns the NetworkMaps's Wireguard configuration.
func WGCfg(nm *netmap.NetworkMap, logf logger.Logf, flags netmap.WGConfigFlags, exitNode tailcfg.StableNodeID) (*wgcfg.Config, error) {
	cfg := &wgcfg.Config{
		Name:       "tailscale",
		PrivateKey: wgkey.Private(nm.PrivateKey),
		Addresses:  nm.Addresses,
		Peers:      make([]wgcfg.Peer, 0, len(nm.Peers)),
	}

	// Logging buffers
	skippedUnselected := new(bytes.Buffer)
	skippedIPs := new(bytes.Buffer)
	skippedSubnets := new(bytes.Buffer)

	for _, peer := range nm.Peers {
		if controlclient.Debug.OnlyDisco && peer.DiscoKey.IsZero() {
			continue
		}
		cfg.Peers = append(cfg.Peers, wgcfg.Peer{
			PublicKey: wgkey.Key(peer.Key),
		})
		cpeer := &cfg.Peers[len(cfg.Peers)-1]
		if peer.KeepAlive {
			cpeer.PersistentKeepalive = 25 // seconds
		}

		if !peer.DiscoKey.IsZero() {
			cpeer.Endpoints = wgcfg.Endpoints{PublicKey: wgkey.Key(peer.Key), DiscoKey: peer.DiscoKey}
		} else {
			if err := appendEndpoint(cpeer, peer.DERP); err != nil {
				return nil, err
			}
			for _, ep := range peer.Endpoints {
				if err := appendEndpoint(cpeer, ep); err != nil {
					return nil, err
				}
			}
		}
		didExitNodeWarn := false
		for _, allowedIP := range peer.AllowedIPs {
			if allowedIP.Bits == 0 && peer.StableID != exitNode {
				if didExitNodeWarn {
					// Don't log about both the IPv4 /0 and IPv6 /0.
					continue
				}
				didExitNodeWarn = true
				if skippedUnselected.Len() > 0 {
					skippedUnselected.WriteString(", ")
				}
				fmt.Fprintf(skippedUnselected, "%q (%v)", nodeDebugName(peer), peer.Key.ShortString())
				continue
			} else if allowedIP.IsSingleIP() && tsaddr.IsTailscaleIP(allowedIP.IP) && (flags&netmap.AllowSingleHosts) == 0 {
				if skippedIPs.Len() > 0 {
					skippedIPs.WriteString(", ")
				}
				fmt.Fprintf(skippedIPs, "%v from %q (%v)", allowedIP.IP, nodeDebugName(peer), peer.Key.ShortString())
				continue
			} else if cidrIsSubnet(peer, allowedIP) {
				if (flags & netmap.AllowSubnetRoutes) == 0 {
					if skippedSubnets.Len() > 0 {
						skippedSubnets.WriteString(", ")
					}
					fmt.Fprintf(skippedSubnets, "%v from %q (%v)", allowedIP, nodeDebugName(peer), peer.Key.ShortString())
					continue
				}
			}
			cpeer.AllowedIPs = append(cpeer.AllowedIPs, allowedIP)
		}
	}

	if skippedUnselected.Len() > 0 {
		logf("[v1] wgcfg: skipped unselected default routes from: %s", skippedUnselected.Bytes())
	}
	if skippedIPs.Len() > 0 {
		logf("[v1] wgcfg: skipped node IPs: %s", skippedIPs)
	}
	if skippedSubnets.Len() > 0 {
		logf("[v1] wgcfg: did not accept subnet routes: %s", skippedSubnets)
	}

	return cfg, nil
}

func appendEndpoint(peer *wgcfg.Peer, epStr string) error {
	if epStr == "" {
		return nil
	}
	ipp, err := netaddr.ParseIPPort(epStr)
	if err != nil {
		return fmt.Errorf("malformed endpoint %q for peer %v", epStr, peer.PublicKey.ShortString())
	}
	peer.Endpoints.IPPorts = append(peer.Endpoints.IPPorts, ipp)
	return nil
}
