// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package wf

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
	"inet.af/wf"
)

// Known addresses.
var (
	linkLocalRange           = netaddr.MustParseIPPrefix("ff80::/10")
	linkLocalDHCPMulticast   = netaddr.MustParseIP("ff02::1:2")
	siteLocalDHCPMulticast   = netaddr.MustParseIP("ff05::1:3")
	linkLocalRouterMulticast = netaddr.MustParseIP("ff02::2")
)

type Direction int

const (
	DirectionInbound Direction = iota
	DirectionOutbound
	DirectionBi
)

type Protocol int

const (
	ProtocolV4 Protocol = iota
	ProtocolV6
	ProtocolAll
)

func (p Protocol) getLayers(d Direction) []wf.LayerID {
	var layers []wf.LayerID
	if p == ProtocolAll || p == ProtocolV4 {
		if d == DirectionBi || d == DirectionInbound {
			layers = append(layers, wf.LayerALEAuthRecvAcceptV4)
		}
		if d == DirectionBi || d == DirectionOutbound {
			layers = append(layers, wf.LayerALEAuthConnectV4)
		}
	}
	if p == ProtocolAll || p == ProtocolV6 {
		if d == DirectionBi || d == DirectionInbound {
			layers = append(layers, wf.LayerALEAuthRecvAcceptV6)
		}
		if d == DirectionBi || d == DirectionOutbound {
			layers = append(layers, wf.LayerALEAuthConnectV6)
		}
	}
	return layers
}

func ruleName(action wf.Action, l wf.LayerID, name string) string {
	switch l {
	case wf.LayerALEAuthConnectV4:
		return fmt.Sprintf("%s outbound %s (IPv4)", action, name)
	case wf.LayerALEAuthConnectV6:
		return fmt.Sprintf("%s outbound %s (IPv6)", action, name)
	case wf.LayerALEAuthRecvAcceptV4:
		return fmt.Sprintf("%s inbound %s (IPv4)", action, name)
	case wf.LayerALEAuthRecvAcceptV6:
		return fmt.Sprintf("%s inbound %s (IPv6)", action, name)
	}
	return ""
}

type Firewall struct {
	luid       uint64
	providerID wf.ProviderID
	sublayerID wf.SublayerID
	session    *wf.Session

	permittedRoutes map[netaddr.IPPrefix][]*wf.Rule
}

func New(luid uint64) (*Firewall, error) {
	session, err := wf.New(&wf.Options{
		Name:    "Tailscale firewall",
		Dynamic: true,
	})
	if err != nil {
		return nil, err
	}
	wguid, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	providerID := wf.ProviderID(wguid)
	if err := session.AddProvider(&wf.Provider{
		ID:   providerID,
		Name: "Tailscale provider",
	}); err != nil {
		return nil, err
	}
	wguid, err = windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	sublayerID := wf.SublayerID(wguid)
	if err := session.AddSublayer(&wf.Sublayer{
		ID:     sublayerID,
		Name:   "Tailscale permissive and blocking filters",
		Weight: 0,
	}); err != nil {
		return nil, err
	}
	return &Firewall{
		luid:            luid,
		session:         session,
		providerID:      providerID,
		sublayerID:      sublayerID,
		permittedRoutes: make(map[netaddr.IPPrefix][]*wf.Rule),
	}, nil
}

func (f *Firewall) Enable() error {
	if err := f.permitTailscaleService(15); err != nil {
		return fmt.Errorf("permitTailscaleService failed: %w", err)
	}

	if err := f.permitDNS(15); err != nil {
		return fmt.Errorf("permitDNS failed: %w", err)
	}

	if err := f.permitLoopback(13); err != nil {
		return fmt.Errorf("permitLoopback failed: %w", err)
	}

	if err := f.permitTunInterface(12); err != nil {
		return fmt.Errorf("permitTunInterface failed: %w", err)
	}

	if err := f.permitDHCPv4(12); err != nil {
		return fmt.Errorf("permitDHCPv4 failed: %w", err)
	}

	if err := f.permitDHCPv6(12); err != nil {
		return fmt.Errorf("permitDHCPv6 failed: %w", err)
	}

	if err := f.permitNDP(12); err != nil {
		return fmt.Errorf("permitNDP failed: %w", err)
	}

	/* TODO: actually evaluate if this does anything and if we need this. It's layer 2; our other rules are layer 3.
	 *  In other words, if somebody complains, try enabling it. For now, keep it off.
	err = permitHyperV(session, baseObjects, 12)
	if err != nil {
		return wrapErr(err)
	}
	*/

	if err := f.blockAll(0); err != nil {
		return fmt.Errorf("blockAll failed: %w", err)
	}
	return nil
}

func (f *Firewall) UpdatePermittedRoutes(newRoutes []netaddr.IPPrefix) error {
	fmt.Println("updating routes", newRoutes)
	var routesToAdd []netaddr.IPPrefix
	routeMap := make(map[netaddr.IPPrefix]bool)
	for _, r := range newRoutes {
		routeMap[r] = true
		if _, ok := f.permittedRoutes[r]; !ok {
			routesToAdd = append(routesToAdd, r)
		}
	}
	var routesToRemove []netaddr.IPPrefix
	for r := range f.permittedRoutes {
		if !routeMap[r] {
			routesToRemove = append(routesToRemove, r)
		}
	}
	for _, r := range routesToRemove {
		fmt.Println("removing route", r)
		for _, rule := range f.permittedRoutes[r] {
			if err := f.session.DeleteRule(rule.ID); err != nil {
				return err
			}
		}
		delete(f.permittedRoutes, r)
	}
	for _, r := range routesToAdd {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: r,
			},
		}
		var p Protocol
		if r.IP.Is4() {
			p = ProtocolV4
		} else {
			p = ProtocolV6
		}
		rules, err := f.addRules("local route", 15, conditions, wf.ActionPermit, p, DirectionBi)
		if err != nil {
			return err
		}
		f.permittedRoutes[r] = rules
	}
	return nil
}

func (f *Firewall) newRule(name string, weight uint64, layer wf.LayerID, conditions []*wf.Match, action wf.Action) (*wf.Rule, error) {
	id, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	return &wf.Rule{
		Name:       ruleName(action, layer, name),
		ID:         wf.RuleID(id),
		Provider:   f.providerID,
		Sublayer:   f.sublayerID,
		HardAction: false,
		Layer:      layer,
		Weight:     weight,
		Conditions: conditions,
		Action:     action,
	}, nil
}

func (f *Firewall) addRules(name string, weight uint64, conditions []*wf.Match, action wf.Action, p Protocol, d Direction) ([]*wf.Rule, error) {
	var rules []*wf.Rule
	for _, l := range p.getLayers(d) {
		r, err := f.newRule(name, weight, l, conditions, action)
		if err != nil {
			return nil, err
		}
		if err := f.session.AddRule(r); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (f *Firewall) blockAll(weight uint64) error {
	_, err := f.addRules("all", weight, nil, wf.ActionBlock, ProtocolAll, DirectionBi)
	return err
}

func (f *Firewall) permitNDP(weight uint64) error {
	fieldICMPType := wf.FieldIPLocalPort
	fieldICMPCode := wf.FieldIPRemotePort

	var icmpConditions = func(t, c uint16, remoteAddress interface{}) []*wf.Match {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoICMPV6,
			},
			{
				Field: fieldICMPType,
				Op:    wf.MatchTypeEqual,
				Value: t,
			},
			{
				Field: fieldICMPCode,
				Op:    wf.MatchTypeEqual,
				Value: c,
			},
		}
		if remoteAddress != nil {
			conditions = append(conditions, &wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: linkLocalRouterMulticast,
			})
		}
		return conditions
	}
	/* TODO: actually handle the hop limit somehow! The rules should vaguely be:
	 *  - icmpv6 133: must be outgoing, dst must be FF02::2/128, hop limit must be 255
	 *  - icmpv6 134: must be incoming, src must be FE80::/10, hop limit must be 255
	 *  - icmpv6 135: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 136: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 137: must be incoming, src must be FE80::/10, hop limit must be 255
	 */

	//
	// Router Solicitation Message
	// ICMP type 133, code 0. Outgoing.
	//
	conditions := icmpConditions(133, 0, linkLocalRouterMulticast)
	if _, err := f.addRules("NDP type 133", weight, conditions, wf.ActionPermit, ProtocolV6, DirectionOutbound); err != nil {
		return err
	}

	//
	// Router Advertisement Message
	// ICMP type 134, code 0. Incoming.
	//
	conditions = icmpConditions(134, 0, linkLocalRange)
	if _, err := f.addRules("NDP type 134", weight, conditions, wf.ActionPermit, ProtocolV6, DirectionInbound); err != nil {
		return err
	}

	//
	// Neighbor Solicitation Message
	// ICMP type 135, code 0. Bi-directional.
	//
	conditions = icmpConditions(135, 0, nil)
	if _, err := f.addRules("NDP type 135", weight, conditions, wf.ActionPermit, ProtocolV6, DirectionBi); err != nil {
		return err
	}

	//
	// Neighbor Advertisement Message
	// ICMP type 136, code 0. Bi-directional.
	//
	conditions = icmpConditions(136, 0, nil)
	if _, err := f.addRules("NDP type 136", weight, conditions, wf.ActionPermit, ProtocolV6, DirectionBi); err != nil {
		return err
	}

	//
	// Redirect Message
	// ICMP type 137, code 0. Incoming.
	//
	conditions = icmpConditions(137, 0, linkLocalRange)
	if _, err := f.addRules("NDP type 137", weight, conditions, wf.ActionPermit, ProtocolV6, DirectionInbound); err != nil {
		return err
	}
	return nil
}

func (f *Firewall) permitDHCPv6(weight uint64) error {
	var dhcpConditions = func(remoteAddrs ...interface{}) []*wf.Match {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoUDP,
			},
			{
				Field: wf.FieldIPLocalAddress,
				Op:    wf.MatchTypeEqual,
				Value: linkLocalRange,
			},
			{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(546),
			},
			{
				Field: wf.FieldIPRemotePort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(547),
			},
		}
		for _, a := range remoteAddrs {
			conditions = append(conditions, &wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: a,
			})
		}
		return conditions
	}
	conditions := dhcpConditions(linkLocalDHCPMulticast, siteLocalDHCPMulticast)
	if _, err := f.addRules("DHCP request", weight, conditions, wf.ActionPermit, ProtocolV6, DirectionOutbound); err != nil {
		return err
	}
	conditions = dhcpConditions(linkLocalRange)
	if _, err := f.addRules("DHCP response", weight, conditions, wf.ActionPermit, ProtocolV6, DirectionInbound); err != nil {
		return err
	}
	return nil
}

func (f *Firewall) permitDHCPv4(weight uint64) error {
	var dhcpConditions = func(remoteAddrs ...interface{}) []*wf.Match {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoUDP,
			},
			{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(68),
			},
			{
				Field: wf.FieldIPRemotePort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(67),
			},
		}
		for _, a := range remoteAddrs {
			conditions = append(conditions, &wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: a,
			})
		}
		return conditions
	}
	conditions := dhcpConditions(netaddr.IPv4(255, 255, 255, 255))
	if _, err := f.addRules("DHCP request", weight, conditions, wf.ActionPermit, ProtocolV4, DirectionOutbound); err != nil {
		return err
	}

	conditions = dhcpConditions()
	if _, err := f.addRules("DHCP response", weight, conditions, wf.ActionPermit, ProtocolV4, DirectionInbound); err != nil {
		return err
	}
	return nil
}

func (f *Firewall) permitTunInterface(weight uint64) error {
	condition := []*wf.Match{
		{
			Field: wf.FieldIPLocalInterface,
			Op:    wf.MatchTypeEqual,
			Value: f.luid,
		},
	}
	_, err := f.addRules("on TUN", weight, condition, wf.ActionPermit, ProtocolAll, DirectionBi)
	return err
}

func (f *Firewall) permitLoopback(weight uint64) error {
	condition := []*wf.Match{
		{
			Field: wf.FieldFlags,
			Op:    wf.MatchTypeEqual,
			Value: wf.ConditionFlagIsLoopback,
		},
	}
	_, err := f.addRules("on loopback", weight, condition, wf.ActionPermit, ProtocolAll, DirectionBi)
	return err
}

func (f *Firewall) permitDNS(weight uint64) error {
	conditions := []*wf.Match{
		{
			Field: wf.FieldIPRemotePort,
			Op:    wf.MatchTypeEqual,
			Value: uint16(53),
		},
		// Repeat the condition type for logical OR.
		{
			Field: wf.FieldIPProtocol,
			Op:    wf.MatchTypeEqual,
			Value: wf.IPProtoUDP,
		},
		{
			Field: wf.FieldIPProtocol,
			Op:    wf.MatchTypeEqual,
			Value: wf.IPProtoTCP,
		},
	}
	_, err := f.addRules("DNS", weight, conditions, wf.ActionPermit, ProtocolAll, DirectionBi)
	return err
}

func (f *Firewall) permitTailscaleService(weight uint64) error {
	currentFile, err := os.Executable()
	if err != nil {
		return err
	}

	appID, err := wf.AppID(currentFile)
	if err != nil {
		return fmt.Errorf("could not get app id for %q: %w", currentFile, err)
	}
	conditions := []*wf.Match{
		{
			Field: wf.FieldALEAppID,
			Op:    wf.MatchTypeEqual,
			Value: appID,
		},
	}
	_, err = f.addRules("unrestricted traffic for Tailscale service", weight, conditions, wf.ActionPermit, ProtocolAll, DirectionBi)
	return err
}
