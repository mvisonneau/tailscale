// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"reflect"
	"testing"

	"inet.af/netaddr"
	"tailscale.com/types/ipproto"
)

const (
	Unknown  = ipproto.Unknown
	TCP      = ipproto.TCP
	UDP      = ipproto.UDP
	SCTP     = ipproto.SCTP
	IGMP     = ipproto.IGMP
	ICMPv4   = ipproto.ICMPv4
	ICMPv6   = ipproto.ICMPv6
	TSMP     = ipproto.TSMP
	Fragment = ipproto.Fragment
)

func mustIPPort(s string) netaddr.IPPort {
	ipp, err := netaddr.ParseIPPort(s)
	if err != nil {
		panic(err)
	}
	return ipp
}

var icmp4RequestBuffer = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x27, 0xde, 0xad, 0x00, 0x00, 0x40, 0x01, 0x8c, 0x15,
	// source ip
	0x01, 0x02, 0x03, 0x04,
	// destination ip
	0x05, 0x06, 0x07, 0x08,
	// ICMP header
	0x08, 0x00, 0x7d, 0x22,
	// "request_payload"
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var icmp4RequestDecode = Parsed{
	b:       icmp4RequestBuffer,
	subofs:  20,
	dataofs: 24,
	length:  len(icmp4RequestBuffer),

	IPVersion: 4,
	IPProto:   ICMPv4,
	Src:       mustIPPort("1.2.3.4:0"),
	Dst:       mustIPPort("5.6.7.8:0"),
}

var icmp4ReplyBuffer = []byte{
	0x45, 0x00, 0x00, 0x25, 0x21, 0x52, 0x00, 0x00, 0x40, 0x01, 0x49, 0x73,
	// source ip
	0x05, 0x06, 0x07, 0x08,
	// destination ip
	0x01, 0x02, 0x03, 0x04,
	// ICMP header
	0x00, 0x00, 0xe6, 0x9e,
	// "reply_payload"
	0x72, 0x65, 0x70, 0x6c, 0x79, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var icmp4ReplyDecode = Parsed{
	b:       icmp4ReplyBuffer,
	subofs:  20,
	dataofs: 24,
	length:  len(icmp4ReplyBuffer),

	IPVersion: 4,
	IPProto:   ICMPv4,
	Src:       mustIPPort("1.2.3.4:0"),
	Dst:       mustIPPort("5.6.7.8:0"),
}

// ICMPv6 Router Solicitation
var icmp6PacketBuffer = []byte{
	0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xfb, 0x57, 0x1d, 0xea, 0x9c, 0x39, 0x8f, 0xb7,
	0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0x85, 0x00, 0x38, 0x04, 0x00, 0x00, 0x00, 0x00,
}

var icmp6PacketDecode = Parsed{
	b:         icmp6PacketBuffer,
	subofs:    40,
	dataofs:   44,
	length:    len(icmp6PacketBuffer),
	IPVersion: 6,
	IPProto:   ICMPv6,
	Src:       mustIPPort("[fe80::fb57:1dea:9c39:8fb7]:0"),
	Dst:       mustIPPort("[ff02::2]:0"),
}

// This is a malformed IPv4 packet.
// Namely, the string "tcp_payload" follows the first byte of the IPv4 header.
var unknownPacketBuffer = []byte{
	0x45, 0x74, 0x63, 0x70, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var unknownPacketDecode = Parsed{
	b:         unknownPacketBuffer,
	IPVersion: 0,
	IPProto:   Unknown,
}

var tcp4PacketBuffer = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x37, 0xde, 0xad, 0x00, 0x00, 0x40, 0x06, 0x49, 0x5f,
	// source ip
	0x01, 0x02, 0x03, 0x04,
	// destination ip
	0x05, 0x06, 0x07, 0x08,
	// TCP header with SYN, ACK set
	0x00, 0x7b, 0x02, 0x37, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
	0x50, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	// "request_payload"
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var tcp4PacketDecode = Parsed{
	b:       tcp4PacketBuffer,
	subofs:  20,
	dataofs: 40,
	length:  len(tcp4PacketBuffer),

	IPVersion: 4,
	IPProto:   TCP,
	Src:       mustIPPort("1.2.3.4:123"),
	Dst:       mustIPPort("5.6.7.8:567"),
	TCPFlags:  TCPSynAck,
}

var tcp6RequestBuffer = []byte{
	// IPv6 header up to hop limit
	0x60, 0x06, 0xef, 0xcc, 0x00, 0x28, 0x06, 0x40,
	// Src addr
	0x20, 0x01, 0x05, 0x59, 0xbc, 0x13, 0x54, 0x00, 0x17, 0x49, 0x46, 0x28, 0x39, 0x34, 0x0e, 0x1b,
	// Dst addr
	0x26, 0x07, 0xf8, 0xb0, 0x40, 0x0a, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e,
	// TCP SYN segment, no payload
	0xa4, 0x60, 0x00, 0x50, 0xf3, 0x82, 0xa1, 0x25, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xfd, 0x20,
	0xb1, 0xc6, 0x00, 0x00, 0x02, 0x04, 0x05, 0xa0, 0x04, 0x02, 0x08, 0x0a, 0xca, 0x76, 0xa6, 0x8e,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
}

var tcp6RequestDecode = Parsed{
	b:       tcp6RequestBuffer,
	subofs:  40,
	dataofs: len(tcp6RequestBuffer),
	length:  len(tcp6RequestBuffer),

	IPVersion: 6,
	IPProto:   TCP,
	Src:       mustIPPort("[2001:559:bc13:5400:1749:4628:3934:e1b]:42080"),
	Dst:       mustIPPort("[2607:f8b0:400a:809::200e]:80"),
	TCPFlags:  TCPSyn,
}

var udp4RequestBuffer = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x2b, 0xde, 0xad, 0x00, 0x00, 0x40, 0x11, 0x8c, 0x01,
	// source ip
	0x01, 0x02, 0x03, 0x04,
	// destination ip
	0x05, 0x06, 0x07, 0x08,
	// UDP header
	0x00, 0x7b, 0x02, 0x37, 0x00, 0x17, 0x72, 0x1d,
	// "request_payload"
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var udp4RequestDecode = Parsed{
	b:       udp4RequestBuffer,
	subofs:  20,
	dataofs: 28,
	length:  len(udp4RequestBuffer),

	IPVersion: 4,
	IPProto:   UDP,
	Src:       mustIPPort("1.2.3.4:123"),
	Dst:       mustIPPort("5.6.7.8:567"),
}

var invalid4RequestBuffer = []byte{
	// IP header up to checksum. IHL field points beyond end of packet.
	0x4a, 0x00, 0x00, 0x14, 0xde, 0xad, 0x00, 0x00, 0x40, 0x11, 0x8c, 0x01,
	// source ip
	0x01, 0x02, 0x03, 0x04,
	// destination ip
	0x05, 0x06, 0x07, 0x08,
}

// Regression check for the IHL field pointing beyond the end of the
// packet.
var invalid4RequestDecode = Parsed{
	b:      invalid4RequestBuffer,
	subofs: 40,
	length: len(invalid4RequestBuffer),

	IPVersion: 4,
	IPProto:   Unknown,
	Src:       mustIPPort("1.2.3.4:0"),
	Dst:       mustIPPort("5.6.7.8:0"),
}

var udp6RequestBuffer = []byte{
	// IPv6 header up to hop limit
	0x60, 0x0e, 0xc9, 0x67, 0x00, 0x29, 0x11, 0x40,
	// Src addr
	0x20, 0x01, 0x05, 0x59, 0xbc, 0x13, 0x54, 0x00, 0x17, 0x49, 0x46, 0x28, 0x39, 0x34, 0x0e, 0x1b,
	// Dst addr
	0x26, 0x07, 0xf8, 0xb0, 0x40, 0x0a, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e,
	// UDP header
	0xd4, 0x04, 0x01, 0xbb, 0x00, 0x29, 0x96, 0x84,
	// Payload
	0x5c, 0x06, 0xae, 0x85, 0x02, 0xf5, 0xdb, 0x90, 0xe0, 0xe0, 0x93, 0xed, 0x9a, 0xd9, 0x92, 0x69, 0xbe, 0x36, 0x8a, 0x7d, 0xd7, 0xce, 0xd0, 0x8a, 0xf2, 0x51, 0x95, 0xff, 0xb6, 0x92, 0x70, 0x10, 0xd7,
}

var udp6RequestDecode = Parsed{
	b:       udp6RequestBuffer,
	subofs:  40,
	dataofs: 48,
	length:  len(udp6RequestBuffer),

	IPVersion: 6,
	IPProto:   UDP,
	Src:       mustIPPort("[2001:559:bc13:5400:1749:4628:3934:e1b]:54276"),
	Dst:       mustIPPort("[2607:f8b0:400a:809::200e]:443"),
}

var udp4ReplyBuffer = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x29, 0x21, 0x52, 0x00, 0x00, 0x40, 0x11, 0x49, 0x5f,
	// source ip
	0x05, 0x06, 0x07, 0x08,
	// destination ip
	0x01, 0x02, 0x03, 0x04,
	// UDP header
	0x02, 0x37, 0x00, 0x7b, 0x00, 0x15, 0xd3, 0x9d,
	// "reply_payload"
	0x72, 0x65, 0x70, 0x6c, 0x79, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var udp4ReplyDecode = Parsed{
	b:       udp4ReplyBuffer,
	subofs:  20,
	dataofs: 28,
	length:  len(udp4ReplyBuffer),

	IPProto: UDP,
	Src:     mustIPPort("1.2.3.4:567"),
	Dst:     mustIPPort("5.6.7.8:123"),
}

var igmpPacketBuffer = []byte{
	// IP header up to checksum
	0x46, 0xc0, 0x00, 0x20, 0x00, 0x00, 0x40, 0x00, 0x01, 0x02, 0x41, 0x22,
	// source IP
	0xc0, 0xa8, 0x01, 0x52,
	// destination IP
	0xe0, 0x00, 0x00, 0xfb,
	// IGMP Membership Report
	0x94, 0x04, 0x00, 0x00, 0x16, 0x00, 0x09, 0x04, 0xe0, 0x00, 0x00, 0xfb,
	//0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var igmpPacketDecode = Parsed{
	b:      igmpPacketBuffer,
	subofs: 24,
	length: len(igmpPacketBuffer),

	IPVersion: 4,
	IPProto:   IGMP,
	Src:       mustIPPort("192.168.1.82:0"),
	Dst:       mustIPPort("224.0.0.251:0"),
}

var ipv4TSMPBuffer = []byte{
	// IPv4 header:
	0x45, 0x00,
	0x00, 0x1b, // 20 + 7 bytes total
	0x00, 0x00, // ID
	0x00, 0x00, // Fragment
	0x40, // TTL
	byte(TSMP),
	0x5f, 0xc3, // header checksum (wrong here)
	// source IP:
	0x64, 0x5e, 0x0c, 0x0e,
	// dest IP:
	0x64, 0x4a, 0x46, 0x03,
	byte(TSMPTypeRejectedConn),
	byte(TCP),
	byte(RejectedDueToACLs),
	0x00, 123, // src port
	0x00, 80, // dst port
}

var ipv4TSMPDecode = Parsed{
	b:         ipv4TSMPBuffer,
	subofs:    20,
	dataofs:   20,
	length:    27,
	IPVersion: 4,
	IPProto:   TSMP,
	Src:       mustIPPort("100.94.12.14:0"),
	Dst:       mustIPPort("100.74.70.3:0"),
}

// IPv4 SCTP
var sctpBuffer = []byte{
	// IPv4 header:
	0x45, 0x00,
	0x00, 0x20, // 20 + 12 bytes total
	0x00, 0x00, // ID
	0x00, 0x00, // Fragment
	0x40, // TTL
	byte(SCTP),
	// Checksum, unchecked:
	1, 2,
	// source IP:
	0x64, 0x5e, 0x0c, 0x0e,
	// dest IP:
	0x64, 0x4a, 0x46, 0x03,
	// Src Port, Dest Port:
	0x00, 0x7b, 0x01, 0xc8,
	// Verification tag:
	1, 2, 3, 4,
	// Checksum: (unchecked)
	5, 6, 7, 8,
}

var sctpDecode = Parsed{
	b:         sctpBuffer,
	subofs:    20,
	length:    20 + 12,
	IPVersion: 4,
	IPProto:   SCTP,
	Src:       mustIPPort("100.94.12.14:123"),
	Dst:       mustIPPort("100.74.70.3:456"),
}

func TestParsedString(t *testing.T) {
	tests := []struct {
		name    string
		qdecode Parsed
		want    string
	}{
		{"tcp4", tcp4PacketDecode, "TCP{1.2.3.4:123 > 5.6.7.8:567}"},
		{"tcp6", tcp6RequestDecode, "TCP{[2001:559:bc13:5400:1749:4628:3934:e1b]:42080 > [2607:f8b0:400a:809::200e]:80}"},
		{"udp4", udp4RequestDecode, "UDP{1.2.3.4:123 > 5.6.7.8:567}"},
		{"udp6", udp6RequestDecode, "UDP{[2001:559:bc13:5400:1749:4628:3934:e1b]:54276 > [2607:f8b0:400a:809::200e]:443}"},
		{"icmp4", icmp4RequestDecode, "ICMPv4{1.2.3.4:0 > 5.6.7.8:0}"},
		{"icmp6", icmp6PacketDecode, "ICMPv6{[fe80::fb57:1dea:9c39:8fb7]:0 > [ff02::2]:0}"},
		{"igmp", igmpPacketDecode, "IGMP{192.168.1.82:0 > 224.0.0.251:0}"},
		{"unknown", unknownPacketDecode, "Unknown{???}"},
		{"ipv4_tsmp", ipv4TSMPDecode, "TSMP{100.94.12.14:0 > 100.74.70.3:0}"},
		{"sctp", sctpDecode, "SCTP{100.94.12.14:123 > 100.74.70.3:456}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.qdecode.String()
			if got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}

	var sink string
	allocs := testing.AllocsPerRun(1000, func() {
		sink = tests[0].qdecode.String()
	})
	_ = sink
	if allocs != 1 {
		t.Errorf("allocs = %v; want 1", allocs)
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want Parsed
	}{
		{"icmp4", icmp4RequestBuffer, icmp4RequestDecode},
		{"icmp6", icmp6PacketBuffer, icmp6PacketDecode},
		{"tcp4", tcp4PacketBuffer, tcp4PacketDecode},
		{"tcp6", tcp6RequestBuffer, tcp6RequestDecode},
		{"udp4", udp4RequestBuffer, udp4RequestDecode},
		{"udp6", udp6RequestBuffer, udp6RequestDecode},
		{"igmp", igmpPacketBuffer, igmpPacketDecode},
		{"unknown", unknownPacketBuffer, unknownPacketDecode},
		{"invalid4", invalid4RequestBuffer, invalid4RequestDecode},
		{"ipv4_tsmp", ipv4TSMPBuffer, ipv4TSMPDecode},
		{"ipv4_sctp", sctpBuffer, sctpDecode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Parsed
			got.Decode(tt.buf)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mismatch\n got: %s %#v\nwant: %s %#v", got.String(), got, tt.want.String(), tt.want)
			}
		})
	}

	allocs := testing.AllocsPerRun(1000, func() {
		var got Parsed
		got.Decode(tests[0].buf)
	})
	if allocs != 0 {
		t.Errorf("allocs = %v; want 0", allocs)
	}
}

func BenchmarkDecode(b *testing.B) {
	benches := []struct {
		name string
		buf  []byte
	}{
		{"tcp4", tcp4PacketBuffer},
		{"tcp6", tcp6RequestBuffer},
		{"udp4", udp4RequestBuffer},
		{"udp6", udp6RequestBuffer},
		{"icmp4", icmp4RequestBuffer},
		{"icmp6", icmp6PacketBuffer},
		{"igmp", igmpPacketBuffer},
		{"unknown", unknownPacketBuffer},
	}

	for _, bench := range benches {
		b.Run(bench.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var p Parsed
				p.Decode(bench.buf)
			}
		})
	}
}

func TestMarshalRequest(t *testing.T) {
	// Too small to hold our packets, but only barely.
	var small [20]byte
	var large [64]byte

	icmpHeader := icmp4RequestDecode.ICMP4Header()
	udpHeader := udp4RequestDecode.UDP4Header()
	tests := []struct {
		name   string
		header Header
		want   []byte
	}{
		{"icmp", &icmpHeader, icmp4RequestBuffer},
		{"udp", &udpHeader, udp4RequestBuffer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.header.Marshal(small[:])
			if err != errSmallBuffer {
				t.Errorf("got err: nil; want: %s", errSmallBuffer)
			}

			dataOffset := tt.header.Len()
			dataLength := copy(large[dataOffset:], []byte("request_payload"))
			end := dataOffset + dataLength
			err = tt.header.Marshal(large[:end])

			if err != nil {
				t.Errorf("got err: %s; want nil", err)
			}

			if !bytes.Equal(large[:end], tt.want) {
				t.Errorf("got %x; want %x", large[:end], tt.want)
			}
		})
	}
}

func TestMarshalResponse(t *testing.T) {
	var buf [64]byte

	icmpHeader := icmp4RequestDecode.ICMP4Header()
	udpHeader := udp4RequestDecode.UDP4Header()

	type HeaderToResponser interface {
		Header
		// ToResponse transforms the header into one for a response packet.
		// For instance, this swaps the source and destination IPs.
		ToResponse()
	}

	tests := []struct {
		name   string
		header HeaderToResponser
		want   []byte
	}{
		{"icmp", &icmpHeader, icmp4ReplyBuffer},
		{"udp", &udpHeader, udp4ReplyBuffer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.header.ToResponse()

			dataOffset := tt.header.Len()
			dataLength := copy(buf[dataOffset:], []byte("reply_payload"))
			end := dataOffset + dataLength
			err := tt.header.Marshal(buf[:end])

			if err != nil {
				t.Errorf("got err: %s; want nil", err)
			}

			if !bytes.Equal(buf[:end], tt.want) {
				t.Errorf("got %x; want %x", buf[:end], tt.want)
			}
		})
	}
}
