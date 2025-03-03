// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
)

func DefaultRouteInterface() (string, error) {
	idx, err := DefaultRouteInterfaceIndex()
	if err != nil {
		return "", err
	}
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		return "", err
	}
	return iface.Name, nil
}

// fetchRoutingTable is a retry loop around route.FetchRIB, fetching NET_RT_DUMP2.
//
// The retry loop is due to a bug in the BSDs (or Go?). See
// https://github.com/tailscale/tailscale/issues/1345
func fetchRoutingTable() (rib []byte, err error) {
	fails := 0
	for {
		rib, err := route.FetchRIB(syscall.AF_UNSPEC, syscall.NET_RT_DUMP2, 0)
		if err == nil {
			return rib, nil
		}
		fails++
		if fails < 10 {
			// Empirically, 1 retry is enough. In a long
			// stress test while toggling wifi on & off, I
			// only saw a few occurrences of 2 and one 3.
			// So 10 should be more plenty.
			if fails > 5 {
				time.Sleep(5 * time.Millisecond)
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("route.FetchRIB: %w", err)
		}
	}
}

func DefaultRouteInterfaceIndex() (int, error) {
	// $ netstat -nr
	// Routing tables
	// Internet:
	// Destination        Gateway            Flags        Netif Expire
	// default            10.0.0.1           UGSc           en0         <-- want this one
	// default            10.0.0.1           UGScI          en1

	// From man netstat:
	// U       RTF_UP           Route usable
	// G       RTF_GATEWAY      Destination requires forwarding by intermediary
	// S       RTF_STATIC       Manually added
	// c       RTF_PRCLONING    Protocol-specified generate new routes on use
	// I       RTF_IFSCOPE      Route is associated with an interface scope

	rib, err := fetchRoutingTable()
	if err != nil {
		return 0, fmt.Errorf("route.FetchRIB: %w", err)
	}
	msgs, err := route.ParseRIB(syscall.NET_RT_IFLIST2, rib)
	if err != nil {
		return 0, fmt.Errorf("route.ParseRIB: %w", err)
	}
	indexSeen := map[int]int{} // index => count
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		const RTF_GATEWAY = 0x2
		const RTF_IFSCOPE = 0x1000000
		if rm.Flags&RTF_GATEWAY == 0 {
			continue
		}
		if rm.Flags&RTF_IFSCOPE != 0 {
			continue
		}
		indexSeen[rm.Index]++
	}
	if len(indexSeen) == 0 {
		return 0, errors.New("no gateway index found")
	}
	if len(indexSeen) == 1 {
		for idx := range indexSeen {
			return idx, nil
		}
	}
	return 0, fmt.Errorf("ambiguous gateway interfaces found: %v", indexSeen)
}

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPDarwinFetchRIB
}

func likelyHomeRouterIPDarwinFetchRIB() (ret netaddr.IP, ok bool) {
	rib, err := fetchRoutingTable()
	if err != nil {
		log.Printf("routerIP/FetchRIB: %v", err)
		return ret, false
	}
	msgs, err := route.ParseRIB(syscall.NET_RT_IFLIST2, rib)
	if err != nil {
		log.Printf("routerIP/ParseRIB: %v", err)
		return ret, false
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		const RTF_GATEWAY = 0x2
		const RTF_IFSCOPE = 0x1000000
		if rm.Flags&RTF_GATEWAY == 0 {
			continue
		}
		if rm.Flags&RTF_IFSCOPE != 0 {
			continue
		}
		if len(rm.Addrs) > unix.RTAX_GATEWAY {
			dst4, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
			if !ok || dst4.IP != ([4]byte{0, 0, 0, 0}) {
				// Expect 0.0.0.0 as DST field.
				continue
			}
			gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
			if !ok {
				continue
			}
			return netaddr.IPv4(gw.IP[0], gw.IP[1], gw.IP[2], gw.IP[3]), true
		}
	}

	return ret, false
}
