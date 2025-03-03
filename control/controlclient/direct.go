// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/nacl/box"
	"inet.af/netaddr"
	"tailscale.com/health"
	"tailscale.com/log/logheap"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netns"
	"tailscale.com/net/tlsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/types/persist"
	"tailscale.com/types/wgkey"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/systemd"
	"tailscale.com/version"
	"tailscale.com/wgengine/monitor"
)

// Direct is the client that connects to a tailcontrol server for a node.
type Direct struct {
	httpc                  *http.Client // HTTP client used to talk to tailcontrol
	serverURL              string       // URL of the tailcontrol server
	timeNow                func() time.Time
	lastPrintMap           time.Time
	newDecompressor        func() (Decompressor, error)
	keepAlive              bool
	logf                   logger.Logf
	linkMon                *monitor.Mon // or nil
	discoPubKey            tailcfg.DiscoKey
	getMachinePrivKey      func() (wgkey.Private, error)
	debugFlags             []string
	keepSharerAndUserSplit bool
	skipIPForwardingCheck  bool

	mu           sync.Mutex // mutex guards the following fields
	serverKey    wgkey.Key
	persist      persist.Persist
	authKey      string
	tryingNewKey wgkey.Private
	expiry       *time.Time
	// hostinfo is mutated in-place while mu is held.
	hostinfo      *tailcfg.Hostinfo // always non-nil
	endpoints     []tailcfg.Endpoint
	everEndpoints bool   // whether we've ever had non-empty endpoints
	localPort     uint16 // or zero to mean auto
}

type Options struct {
	Persist              persist.Persist               // initial persistent data
	GetMachinePrivateKey func() (wgkey.Private, error) // returns the machine key to use
	ServerURL            string                        // URL of the tailcontrol server
	AuthKey              string                        // optional node auth key for auto registration
	TimeNow              func() time.Time              // time.Now implementation used by Client
	Hostinfo             *tailcfg.Hostinfo             // non-nil passes ownership, nil means to use default using os.Hostname, etc
	DiscoPublicKey       tailcfg.DiscoKey
	NewDecompressor      func() (Decompressor, error)
	KeepAlive            bool
	Logf                 logger.Logf
	HTTPTestClient       *http.Client // optional HTTP client to use (for tests only)
	DebugFlags           []string     // debug settings to send to control
	LinkMonitor          *monitor.Mon // optional link monitor

	// KeepSharerAndUserSplit controls whether the client
	// understands Node.Sharer. If false, the Sharer is mapped to the User.
	KeepSharerAndUserSplit bool

	// SkipIPForwardingCheck declares that the host's IP
	// forwarding works and should not be double-checked by the
	// controlclient package.
	SkipIPForwardingCheck bool
}

type Decompressor interface {
	DecodeAll(input, dst []byte) ([]byte, error)
	Close()
}

// NewDirect returns a new Direct client.
func NewDirect(opts Options) (*Direct, error) {
	if opts.ServerURL == "" {
		return nil, errors.New("controlclient.New: no server URL specified")
	}
	if opts.GetMachinePrivateKey == nil {
		return nil, errors.New("controlclient.New: no GetMachinePrivateKey specified")
	}
	opts.ServerURL = strings.TrimRight(opts.ServerURL, "/")
	serverURL, err := url.Parse(opts.ServerURL)
	if err != nil {
		return nil, err
	}
	if opts.TimeNow == nil {
		opts.TimeNow = time.Now
	}
	if opts.Logf == nil {
		// TODO(apenwarr): remove this default and fail instead.
		// TODO(bradfitz): ... but then it shouldn't be in Options.
		opts.Logf = log.Printf
	}

	httpc := opts.HTTPTestClient
	if httpc == nil {
		dnsCache := &dnscache.Resolver{
			Forward:          dnscache.Get().Forward, // use default cache's forwarder
			UseLastGood:      true,
			LookupIPFallback: dnsfallback.Lookup,
		}
		dialer := netns.NewDialer()
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = tshttpproxy.ProxyFromEnvironment
		tshttpproxy.SetTransportGetProxyConnectHeader(tr)
		tr.TLSClientConfig = tlsdial.Config(serverURL.Hostname(), tr.TLSClientConfig)
		tr.DialContext = dnscache.Dialer(dialer.DialContext, dnsCache)
		tr.DialTLSContext = dnscache.TLSDialer(dialer.DialContext, dnsCache, tr.TLSClientConfig)
		tr.ForceAttemptHTTP2 = true
		httpc = &http.Client{Transport: tr}
	}

	c := &Direct{
		httpc:                  httpc,
		getMachinePrivKey:      opts.GetMachinePrivateKey,
		serverURL:              opts.ServerURL,
		timeNow:                opts.TimeNow,
		logf:                   opts.Logf,
		newDecompressor:        opts.NewDecompressor,
		keepAlive:              opts.KeepAlive,
		persist:                opts.Persist,
		authKey:                opts.AuthKey,
		discoPubKey:            opts.DiscoPublicKey,
		debugFlags:             opts.DebugFlags,
		keepSharerAndUserSplit: opts.KeepSharerAndUserSplit,
		linkMon:                opts.LinkMonitor,
		skipIPForwardingCheck:  opts.SkipIPForwardingCheck,
	}
	if opts.Hostinfo == nil {
		c.SetHostinfo(NewHostinfo())
	} else {
		c.SetHostinfo(opts.Hostinfo)
	}
	return c, nil
}

var osVersion func() string // non-nil on some platforms

func NewHostinfo() *tailcfg.Hostinfo {
	hostname, _ := os.Hostname()
	hostname = dnsname.FirstLabel(hostname)
	var osv string
	if osVersion != nil {
		osv = osVersion()
	}
	return &tailcfg.Hostinfo{
		IPNVersion: version.Long,
		Hostname:   hostname,
		OS:         version.OS(),
		OSVersion:  osv,
		Package:    packageType(),
		GoArch:     runtime.GOARCH,
	}
}

func packageType() string {
	switch runtime.GOOS {
	case "windows":
		if _, err := os.Stat(`C:\ProgramData\chocolatey\lib\tailscale`); err == nil {
			return "choco"
		}
	case "darwin":
		// Using tailscaled or IPNExtension?
		exe, _ := os.Executable()
		return filepath.Base(exe)
	}
	return ""
}

// SetHostinfo clones the provided Hostinfo and remembers it for the
// next update. It reports whether the Hostinfo has changed.
func (c *Direct) SetHostinfo(hi *tailcfg.Hostinfo) bool {
	if hi == nil {
		panic("nil Hostinfo")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if hi.Equal(c.hostinfo) {
		return false
	}
	c.hostinfo = hi.Clone()
	j, _ := json.Marshal(c.hostinfo)
	c.logf("HostInfo: %s", j)
	return true
}

// SetNetInfo clones the provided NetInfo and remembers it for the
// next update. It reports whether the NetInfo has changed.
func (c *Direct) SetNetInfo(ni *tailcfg.NetInfo) bool {
	if ni == nil {
		panic("nil NetInfo")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hostinfo == nil {
		c.logf("[unexpected] SetNetInfo called with no HostInfo; ignoring NetInfo update: %+v", ni)
		return false
	}
	if reflect.DeepEqual(ni, c.hostinfo.NetInfo) {
		return false
	}
	c.hostinfo.NetInfo = ni.Clone()
	return true
}

func (c *Direct) GetPersist() persist.Persist {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.persist
}

func (c *Direct) TryLogout(ctx context.Context) error {
	c.logf("direct.TryLogout()")

	mustRegen, newURL, err := c.doLogin(ctx, loginOpt{Logout: true})
	c.logf("TryLogout control response: mustRegen=%v, newURL=%v, err=%v", mustRegen, newURL, err)

	c.mu.Lock()
	c.persist = persist.Persist{}
	c.mu.Unlock()

	return err
}

func (c *Direct) TryLogin(ctx context.Context, t *tailcfg.Oauth2Token, flags LoginFlags) (url string, err error) {
	c.logf("direct.TryLogin(token=%v, flags=%v)", t != nil, flags)
	return c.doLoginOrRegen(ctx, loginOpt{Token: t, Flags: flags})
}

// WaitLoginURL sits in a long poll waiting for the user to authenticate at url.
//
// On success, newURL and err will both be nil.
func (c *Direct) WaitLoginURL(ctx context.Context, url string) (newURL string, err error) {
	c.logf("direct.WaitLoginURL")
	return c.doLoginOrRegen(ctx, loginOpt{URL: url})
}

func (c *Direct) doLoginOrRegen(ctx context.Context, opt loginOpt) (newURL string, err error) {
	mustRegen, url, err := c.doLogin(ctx, opt)
	if err != nil {
		return url, err
	}
	if mustRegen {
		opt.Regen = true
		_, url, err = c.doLogin(ctx, opt)
	}
	return url, err
}

type loginOpt struct {
	Token  *tailcfg.Oauth2Token
	Flags  LoginFlags
	Regen  bool
	URL    string
	Logout bool
}

func (c *Direct) doLogin(ctx context.Context, opt loginOpt) (mustRegen bool, newURL string, err error) {
	c.mu.Lock()
	persist := c.persist
	tryingNewKey := c.tryingNewKey
	serverKey := c.serverKey
	authKey := c.authKey
	hostinfo := c.hostinfo.Clone()
	backendLogID := hostinfo.BackendLogID
	expired := c.expiry != nil && !c.expiry.IsZero() && c.expiry.Before(c.timeNow())
	c.mu.Unlock()

	machinePrivKey, err := c.getMachinePrivKey()
	if err != nil {
		return false, "", fmt.Errorf("getMachinePrivKey: %w", err)
	}
	if machinePrivKey.IsZero() {
		return false, "", errors.New("getMachinePrivKey returned zero key")
	}

	regen := opt.Regen
	if opt.Logout {
		c.logf("logging out...")
	} else {
		if expired {
			c.logf("Old key expired -> regen=true")
			systemd.Status("key expired; run 'tailscale up' to authenticate")
			regen = true
		}
		if (opt.Flags & LoginInteractive) != 0 {
			c.logf("LoginInteractive -> regen=true")
			regen = true
		}
	}

	c.logf("doLogin(regen=%v, hasUrl=%v)", regen, opt.URL != "")
	if serverKey.IsZero() {
		var err error
		serverKey, err = loadServerKey(ctx, c.httpc, c.serverURL)
		if err != nil {
			return regen, opt.URL, err
		}

		c.mu.Lock()
		c.serverKey = serverKey
		c.mu.Unlock()
	}

	var oldNodeKey wgkey.Key
	switch {
	case opt.Logout:
		tryingNewKey = persist.PrivateNodeKey
	case opt.URL != "":
		// Nothing.
	case regen || persist.PrivateNodeKey.IsZero():
		c.logf("Generating a new nodekey.")
		persist.OldPrivateNodeKey = persist.PrivateNodeKey
		key, err := wgkey.NewPrivate()
		if err != nil {
			c.logf("login keygen: %v", err)
			return regen, opt.URL, err
		}
		tryingNewKey = key
	default:
		// Try refreshing the current key first
		tryingNewKey = persist.PrivateNodeKey
	}
	if !persist.OldPrivateNodeKey.IsZero() {
		oldNodeKey = persist.OldPrivateNodeKey.Public()
	}

	if tryingNewKey.IsZero() {
		if opt.Logout {
			return false, "", errors.New("no nodekey to log out")
		}
		log.Fatalf("tryingNewKey is empty, give up")
	}
	if backendLogID == "" {
		err = errors.New("hostinfo: BackendLogID missing")
		return regen, opt.URL, err
	}
	now := time.Now().Round(time.Second)
	request := tailcfg.RegisterRequest{
		Version:    1,
		OldNodeKey: tailcfg.NodeKey(oldNodeKey),
		NodeKey:    tailcfg.NodeKey(tryingNewKey.Public()),
		Hostinfo:   hostinfo,
		Followup:   opt.URL,
		Timestamp:  &now,
	}
	if opt.Logout {
		request.Expiry = time.Unix(123, 0) // far in the past
	}
	c.logf("RegisterReq: onode=%v node=%v fup=%v",
		request.OldNodeKey.ShortString(),
		request.NodeKey.ShortString(), opt.URL != "")
	request.Auth.Oauth2Token = opt.Token
	request.Auth.Provider = persist.Provider
	request.Auth.LoginName = persist.LoginName
	request.Auth.AuthKey = authKey
	err = signRegisterRequest(&request, c.serverURL, c.serverKey, machinePrivKey.Public())
	if err != nil {
		// If signing failed, clear all related fields
		request.SignatureType = tailcfg.SignatureNone
		request.Timestamp = nil
		request.DeviceCert = nil
		request.Signature = nil

		// Don't log the common error types. Signatures are not usually enabled,
		// so these are expected.
		if !errors.Is(err, errCertificateNotConfigured) && !errors.Is(err, errNoCertStore) {
			c.logf("RegisterReq sign error: %v", err)
		}
	}
	if debugRegister {
		j, _ := json.MarshalIndent(request, "", "\t")
		c.logf("RegisterRequest: %s", j)
	}

	bodyData, err := encode(request, &serverKey, &machinePrivKey)
	if err != nil {
		return regen, opt.URL, err
	}
	body := bytes.NewReader(bodyData)

	u := fmt.Sprintf("%s/machine/%s", c.serverURL, machinePrivKey.Public().HexString())
	req, err := http.NewRequest("POST", u, body)
	if err != nil {
		return regen, opt.URL, err
	}
	req = req.WithContext(ctx)

	res, err := c.httpc.Do(req)
	if err != nil {
		return regen, opt.URL, fmt.Errorf("register request: %v", err)
	}
	if res.StatusCode != 200 {
		msg, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return regen, opt.URL, fmt.Errorf("register request: http %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}
	resp := tailcfg.RegisterResponse{}
	if err := decode(res, &resp, &serverKey, &machinePrivKey); err != nil {
		c.logf("error decoding RegisterResponse with server key %s and machine key %s: %v", serverKey, machinePrivKey.Public(), err)
		return regen, opt.URL, fmt.Errorf("register request: %v", err)
	}
	if debugRegister {
		j, _ := json.MarshalIndent(resp, "", "\t")
		c.logf("RegisterResponse: %s", j)
	}

	// Log without PII:
	c.logf("RegisterReq: got response; nodeKeyExpired=%v, machineAuthorized=%v; authURL=%v",
		resp.NodeKeyExpired, resp.MachineAuthorized, resp.AuthURL != "")

	if resp.NodeKeyExpired {
		if regen {
			return true, "", fmt.Errorf("weird: regen=true but server says NodeKeyExpired: %v", request.NodeKey)
		}
		c.logf("server reports new node key %v has expired",
			request.NodeKey.ShortString())
		return true, "", nil
	}
	if persist.Provider == "" {
		persist.Provider = resp.Login.Provider
	}
	if persist.LoginName == "" {
		persist.LoginName = resp.Login.LoginName
	}

	// TODO(crawshaw): RegisterResponse should be able to mechanically
	// communicate some extra instructions from the server:
	//	- new node key required
	//	- machine key no longer supported
	//	- user is disabled

	if resp.AuthURL != "" {
		c.logf("AuthURL is %v", resp.AuthURL)
	} else {
		c.logf("No AuthURL")
	}

	c.mu.Lock()
	if resp.AuthURL == "" {
		// key rotation is complete
		persist.PrivateNodeKey = tryingNewKey
	} else {
		// save it for the retry-with-URL
		c.tryingNewKey = tryingNewKey
	}
	c.persist = persist
	c.mu.Unlock()

	if err != nil {
		return regen, "", err
	}
	if ctx.Err() != nil {
		return regen, "", ctx.Err()
	}
	return false, resp.AuthURL, nil
}

func sameEndpoints(a, b []tailcfg.Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// newEndpoints acquires c.mu and sets the local port and endpoints and reports
// whether they've changed.
//
// It does not retain the provided slice.
func (c *Direct) newEndpoints(localPort uint16, endpoints []tailcfg.Endpoint) (changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Nothing new?
	if c.localPort == localPort && sameEndpoints(c.endpoints, endpoints) {
		return false // unchanged
	}
	var epStrs []string
	for _, ep := range endpoints {
		epStrs = append(epStrs, ep.Addr.String())
	}
	c.logf("client.newEndpoints(%v, %v)", localPort, epStrs)
	c.localPort = localPort
	c.endpoints = append(c.endpoints[:0], endpoints...)
	if len(endpoints) > 0 {
		c.everEndpoints = true
	}
	return true // changed
}

// SetEndpoints updates the list of locally advertised endpoints.
// It won't be replicated to the server until a *fresh* call to PollNetMap().
// You don't need to restart PollNetMap if we return changed==false.
func (c *Direct) SetEndpoints(localPort uint16, endpoints []tailcfg.Endpoint) (changed bool) {
	// (no log message on function entry, because it clutters the logs
	//  if endpoints haven't changed. newEndpoints() will log it.)
	return c.newEndpoints(localPort, endpoints)
}

func inTest() bool { return flag.Lookup("test.v") != nil }

// PollNetMap makes a /map request to download the network map, calling cb with
// each new netmap.
//
// maxPolls is how many network maps to download; common values are 1
// or -1 (to keep a long-poll query open to the server).
func (c *Direct) PollNetMap(ctx context.Context, maxPolls int, cb func(*netmap.NetworkMap)) error {
	return c.sendMapRequest(ctx, maxPolls, cb)
}

// SendLiteMapUpdate makes a /map request to update the server of our latest state,
// but does not fetch anything. It returns an error if the server did not return a
// successful 200 OK response.
func (c *Direct) SendLiteMapUpdate(ctx context.Context) error {
	return c.sendMapRequest(ctx, 1, nil)
}

// If we go more than pollTimeout without hearing from the server,
// end the long poll. We should be receiving a keep alive ping
// every minute.
const pollTimeout = 120 * time.Second

// cb nil means to omit peers.
func (c *Direct) sendMapRequest(ctx context.Context, maxPolls int, cb func(*netmap.NetworkMap)) error {
	c.mu.Lock()
	persist := c.persist
	serverURL := c.serverURL
	serverKey := c.serverKey
	hostinfo := c.hostinfo.Clone()
	backendLogID := hostinfo.BackendLogID
	localPort := c.localPort
	var epStrs []string
	var epTypes []tailcfg.EndpointType
	for _, ep := range c.endpoints {
		epStrs = append(epStrs, ep.Addr.String())
		epTypes = append(epTypes, ep.Type)
	}
	everEndpoints := c.everEndpoints
	c.mu.Unlock()

	machinePrivKey, err := c.getMachinePrivKey()
	if err != nil {
		return fmt.Errorf("getMachinePrivKey: %w", err)
	}
	if machinePrivKey.IsZero() {
		return errors.New("getMachinePrivKey returned zero key")
	}

	if persist.PrivateNodeKey.IsZero() {
		return errors.New("privateNodeKey is zero")
	}
	if backendLogID == "" {
		return errors.New("hostinfo: BackendLogID missing")
	}

	allowStream := maxPolls != 1
	c.logf("[v1] PollNetMap: stream=%v :%v ep=%v", allowStream, localPort, epStrs)

	vlogf := logger.Discard
	if Debug.NetMap {
		// TODO(bradfitz): update this to use "[v2]" prefix perhaps? but we don't
		// want to upload it always.
		vlogf = c.logf
	}

	request := &tailcfg.MapRequest{
		Version:       tailcfg.CurrentMapRequestVersion,
		KeepAlive:     c.keepAlive,
		NodeKey:       tailcfg.NodeKey(persist.PrivateNodeKey.Public()),
		DiscoKey:      c.discoPubKey,
		Endpoints:     epStrs,
		EndpointTypes: epTypes,
		Stream:        allowStream,
		Hostinfo:      hostinfo,
		DebugFlags:    c.debugFlags,
		OmitPeers:     cb == nil,
	}
	var extraDebugFlags []string
	if hostinfo != nil && c.linkMon != nil && !c.skipIPForwardingCheck &&
		ipForwardingBroken(hostinfo.RoutableIPs, c.linkMon.InterfaceState()) {
		extraDebugFlags = append(extraDebugFlags, "warn-ip-forwarding-off")
	}
	if health.RouterHealth() != nil {
		extraDebugFlags = append(extraDebugFlags, "warn-router-unhealthy")
	}
	if health.NetworkCategoryHealth() != nil {
		extraDebugFlags = append(extraDebugFlags, "warn-network-category-unhealthy")
	}
	if len(extraDebugFlags) > 0 {
		old := request.DebugFlags
		request.DebugFlags = append(old[:len(old):len(old)], extraDebugFlags...)
	}
	if c.newDecompressor != nil {
		request.Compress = "zstd"
	}
	// On initial startup before we know our endpoints, set the ReadOnly flag
	// to tell the control server not to distribute out our (empty) endpoints to peers.
	// Presumably we'll learn our endpoints in a half second and do another post
	// with useful results. The first POST just gets us the DERP map which we
	// need to do the STUN queries to discover our endpoints.
	// TODO(bradfitz): we skip this optimization in tests, though,
	// because the e2e tests are currently hyperspecific about the
	// ordering of things. The e2e tests need love.
	if len(epStrs) == 0 && !everEndpoints && !inTest() {
		request.ReadOnly = true
	}

	bodyData, err := encode(request, &serverKey, &machinePrivKey)
	if err != nil {
		vlogf("netmap: encode: %v", err)
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	machinePubKey := tailcfg.MachineKey(machinePrivKey.Public())
	t0 := time.Now()
	u := fmt.Sprintf("%s/machine/%s/map", serverURL, machinePubKey.HexString())

	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(bodyData))
	if err != nil {
		return err
	}

	res, err := c.httpc.Do(req)
	if err != nil {
		vlogf("netmap: Do: %v", err)
		return err
	}
	vlogf("netmap: Do = %v after %v", res.StatusCode, time.Since(t0).Round(time.Millisecond))
	if res.StatusCode != 200 {
		msg, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return fmt.Errorf("initial fetch failed %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}
	defer res.Body.Close()

	health.NoteMapRequestHeard(request)

	if cb == nil {
		io.Copy(ioutil.Discard, res.Body)
		return nil
	}

	timeout := time.NewTimer(pollTimeout)
	timeoutReset := make(chan struct{})
	pollDone := make(chan struct{})
	defer close(pollDone)
	go func() {
		for {
			select {
			case <-pollDone:
				vlogf("netmap: ending timeout goroutine")
				return
			case <-timeout.C:
				c.logf("map response long-poll timed out!")
				cancel()
				return
			case <-timeoutReset:
				if !timeout.Stop() {
					select {
					case <-timeout.C:
					case <-pollDone:
						vlogf("netmap: ending timeout goroutine")
						return
					}
				}
				vlogf("netmap: reset timeout timer")
				timeout.Reset(pollTimeout)
			}
		}
	}()

	sess := newMapSession(persist.PrivateNodeKey)
	sess.logf = c.logf
	sess.vlogf = vlogf
	sess.machinePubKey = machinePubKey
	sess.keepSharerAndUserSplit = c.keepSharerAndUserSplit

	// If allowStream, then the server will use an HTTP long poll to
	// return incremental results. There is always one response right
	// away, followed by a delay, and eventually others.
	// If !allowStream, it'll still send the first result in exactly
	// the same format before just closing the connection.
	// We can use this same read loop either way.
	var msg []byte
	for i := 0; i < maxPolls || maxPolls < 0; i++ {
		vlogf("netmap: starting size read after %v (poll %v)", time.Since(t0).Round(time.Millisecond), i)
		var siz [4]byte
		if _, err := io.ReadFull(res.Body, siz[:]); err != nil {
			vlogf("netmap: size read error after %v: %v", time.Since(t0).Round(time.Millisecond), err)
			return err
		}
		size := binary.LittleEndian.Uint32(siz[:])
		vlogf("netmap: read size %v after %v", size, time.Since(t0).Round(time.Millisecond))
		msg = append(msg[:0], make([]byte, size)...)
		if _, err := io.ReadFull(res.Body, msg); err != nil {
			vlogf("netmap: body read error: %v", err)
			return err
		}
		vlogf("netmap: read body after %v", time.Since(t0).Round(time.Millisecond))

		var resp tailcfg.MapResponse
		if err := c.decodeMsg(msg, &resp, &machinePrivKey); err != nil {
			vlogf("netmap: decode error: %v")
			return err
		}

		if allowStream {
			health.GotStreamedMapResponse()
		}

		if pr := resp.PingRequest; pr != nil {
			go answerPing(c.logf, c.httpc, pr)
		}

		if resp.KeepAlive {
			vlogf("netmap: got keep-alive")
		} else {
			vlogf("netmap: got new map")
		}
		select {
		case timeoutReset <- struct{}{}:
			vlogf("netmap: sent timer reset")
		case <-ctx.Done():
			c.logf("[v1] netmap: not resetting timer; context done: %v", ctx.Err())
			return ctx.Err()
		}
		if resp.KeepAlive {
			continue
		}

		if resp.Debug != nil {
			if resp.Debug.LogHeapPprof {
				go logheap.LogHeap(resp.Debug.LogHeapURL)
			}
			if resp.Debug.GoroutineDumpURL != "" {
				go dumpGoroutinesToURL(c.httpc, resp.Debug.GoroutineDumpURL)
			}
			setControlAtomic(&controlUseDERPRoute, resp.Debug.DERPRoute)
			setControlAtomic(&controlTrimWGConfig, resp.Debug.TrimWGConfig)
			if sleep := time.Duration(resp.Debug.SleepSeconds * float64(time.Second)); sleep > 0 {
				if err := sleepAsRequested(ctx, c.logf, timeoutReset, sleep); err != nil {
					return err
				}
			}
		}

		nm := sess.netmapForResponse(&resp)
		if nm.SelfNode == nil {
			c.logf("MapResponse lacked node")
			return errors.New("MapResponse lacked node")
		}

		// Temporarily (2020-06-29) support removing all but
		// discovery-supporting nodes during development, for
		// less noise.
		if Debug.OnlyDisco {
			anyOld, numDisco := false, 0
			for _, p := range nm.Peers {
				if p.DiscoKey.IsZero() {
					anyOld = true
				} else {
					numDisco++
				}
			}
			if anyOld {
				filtered := make([]*tailcfg.Node, 0, numDisco)
				for _, p := range nm.Peers {
					if !p.DiscoKey.IsZero() {
						filtered = append(filtered, p)
					}
				}
				nm.Peers = filtered
			}
		}
		if Debug.StripEndpoints {
			for _, p := range resp.Peers {
				// We need at least one endpoint here for now else
				// other code doesn't even create the discoEndpoint.
				// TODO(bradfitz): fix that and then just nil this out.
				p.Endpoints = []string{"127.9.9.9:456"}
			}
		}
		if Debug.StripCaps {
			nm.SelfNode.Capabilities = nil
		}

		// Get latest localPort. This might've changed if
		// a lite map update occured meanwhile. This only affects
		// the end-to-end test.
		// TODO(bradfitz): remove the NetworkMap.LocalPort field entirely.
		c.mu.Lock()
		nm.LocalPort = c.localPort
		c.mu.Unlock()

		// Printing the netmap can be extremely verbose, but is very
		// handy for debugging. Let's limit how often we do it.
		// Code elsewhere prints netmap diffs every time, so this
		// occasional full dump, plus incremental diffs, should do
		// the job.
		now := c.timeNow()
		if now.Sub(c.lastPrintMap) >= 5*time.Minute {
			c.lastPrintMap = now
			c.logf("[v1] new network map[%d]:\n%s", i, nm.Concise())
		}

		c.mu.Lock()
		c.expiry = &nm.Expiry
		c.mu.Unlock()

		cb(nm)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func decode(res *http.Response, v interface{}, serverKey *wgkey.Key, mkey *wgkey.Private) error {
	defer res.Body.Close()
	msg, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("%d: %v", res.StatusCode, string(msg))
	}
	return decodeMsg(msg, v, serverKey, mkey)
}

var (
	debugMap, _      = strconv.ParseBool(os.Getenv("TS_DEBUG_MAP"))
	debugRegister, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_REGISTER"))
)

var jsonEscapedZero = []byte(`\u0000`)

func (c *Direct) decodeMsg(msg []byte, v interface{}, machinePrivKey *wgkey.Private) error {
	c.mu.Lock()
	serverKey := c.serverKey
	c.mu.Unlock()

	decrypted, err := decryptMsg(msg, &serverKey, machinePrivKey)
	if err != nil {
		return err
	}
	var b []byte
	if c.newDecompressor == nil {
		b = decrypted
	} else {
		decoder, err := c.newDecompressor()
		if err != nil {
			return err
		}
		defer decoder.Close()
		b, err = decoder.DecodeAll(decrypted, nil)
		if err != nil {
			return err
		}
	}
	if debugMap {
		var buf bytes.Buffer
		json.Indent(&buf, b, "", "    ")
		log.Printf("MapResponse: %s", buf.Bytes())
	}

	if bytes.Contains(b, jsonEscapedZero) {
		log.Printf("[unexpected] zero byte in controlclient.Direct.decodeMsg into %T: %q", v, b)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("response: %v", err)
	}
	return nil

}

func decodeMsg(msg []byte, v interface{}, serverKey *wgkey.Key, machinePrivKey *wgkey.Private) error {
	decrypted, err := decryptMsg(msg, serverKey, machinePrivKey)
	if err != nil {
		return err
	}
	if bytes.Contains(decrypted, jsonEscapedZero) {
		log.Printf("[unexpected] zero byte in controlclient decodeMsg into %T: %q", v, decrypted)
	}
	if err := json.Unmarshal(decrypted, v); err != nil {
		return fmt.Errorf("response: %v", err)
	}
	return nil
}

func decryptMsg(msg []byte, serverKey *wgkey.Key, mkey *wgkey.Private) ([]byte, error) {
	var nonce [24]byte
	if len(msg) < len(nonce)+1 {
		return nil, fmt.Errorf("response missing nonce, len=%d", len(msg))
	}
	copy(nonce[:], msg)
	msg = msg[len(nonce):]

	pub, pri := (*[32]byte)(serverKey), (*[32]byte)(mkey)
	decrypted, ok := box.Open(nil, msg, &nonce, pub, pri)
	if !ok {
		return nil, fmt.Errorf("cannot decrypt response (len %d + nonce %d = %d)", len(msg), len(nonce), len(msg)+len(nonce))
	}
	return decrypted, nil
}

func encode(v interface{}, serverKey *wgkey.Key, mkey *wgkey.Private) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if debugMap {
		if _, ok := v.(*tailcfg.MapRequest); ok {
			log.Printf("MapRequest: %s", b)
		}
	}
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	pub, pri := (*[32]byte)(serverKey), (*[32]byte)(mkey)
	msg := box.Seal(nonce[:], b, &nonce, pub, pri)
	return msg, nil
}

func loadServerKey(ctx context.Context, httpc *http.Client, serverURL string) (wgkey.Key, error) {
	req, err := http.NewRequest("GET", serverURL+"/key", nil)
	if err != nil {
		return wgkey.Key{}, fmt.Errorf("create control key request: %v", err)
	}
	req = req.WithContext(ctx)
	res, err := httpc.Do(req)
	if err != nil {
		return wgkey.Key{}, fmt.Errorf("fetch control key: %v", err)
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<16))
	if err != nil {
		return wgkey.Key{}, fmt.Errorf("fetch control key response: %v", err)
	}
	if res.StatusCode != 200 {
		return wgkey.Key{}, fmt.Errorf("fetch control key: %d: %s", res.StatusCode, string(b))
	}
	key, err := wgkey.ParseHex(string(b))
	if err != nil {
		return wgkey.Key{}, fmt.Errorf("fetch control key: %v", err)
	}
	return key, nil
}

// Debug contains temporary internal-only debug knobs.
// They're unexported to not draw attention to them.
var Debug = initDebug()

type debug struct {
	NetMap         bool
	ProxyDNS       bool
	OnlyDisco      bool
	Disco          bool
	StripEndpoints bool // strip endpoints from control (only use disco messages)
	StripCaps      bool // strip all local node's control-provided capabilities
}

func initDebug() debug {
	use := os.Getenv("TS_DEBUG_USE_DISCO")
	return debug{
		NetMap:         envBool("TS_DEBUG_NETMAP"),
		ProxyDNS:       envBool("TS_DEBUG_PROXY_DNS"),
		StripEndpoints: envBool("TS_DEBUG_STRIP_ENDPOINTS"),
		StripCaps:      envBool("TS_DEBUG_STRIP_CAPS"),
		OnlyDisco:      use == "only",
		Disco:          use == "only" || use == "" || envBool("TS_DEBUG_USE_DISCO"),
	}
}

func envBool(k string) bool {
	e := os.Getenv(k)
	if e == "" {
		return false
	}
	v, err := strconv.ParseBool(e)
	if err != nil {
		panic(fmt.Sprintf("invalid non-bool %q for env var %q", e, k))
	}
	return v
}

var clockNow = time.Now

// opt.Bool configs from control.
var (
	controlUseDERPRoute atomic.Value
	controlTrimWGConfig atomic.Value
)

func setControlAtomic(dst *atomic.Value, v opt.Bool) {
	old, ok := dst.Load().(opt.Bool)
	if !ok || old != v {
		dst.Store(v)
	}
}

// DERPRouteFlag reports the last reported value from control for whether
// DERP route optimization (Issue 150) should be enabled.
func DERPRouteFlag() opt.Bool {
	v, _ := controlUseDERPRoute.Load().(opt.Bool)
	return v
}

// TrimWGConfig reports the last reported value from control for whether
// we should do lazy wireguard configuration.
func TrimWGConfig() opt.Bool {
	v, _ := controlTrimWGConfig.Load().(opt.Bool)
	return v
}

// ipForwardingBroken reports whether the system's IP forwarding is disabled
// and will definitely not work for the routes provided.
//
// It should not return false positives.
//
// TODO(bradfitz): merge this code into LocalBackend.CheckIPForwarding
// and change controlclient.Options.SkipIPForwardingCheck into a
// func([]netaddr.IPPrefix) error signature instead. Then we only have
// one copy of this code.
func ipForwardingBroken(routes []netaddr.IPPrefix, state *interfaces.State) bool {
	if len(routes) == 0 {
		// Nothing to route, so no need to warn.
		return false
	}

	if runtime.GOOS != "linux" {
		// We only do subnet routing on Linux for now.
		// It might work on darwin/macOS when building from source, so
		// don't return true for other OSes. We can OS-based warnings
		// already in the admin panel.
		return false
	}

	localIPs := map[netaddr.IP]bool{}
	for _, addrs := range state.InterfaceIPs {
		for _, pfx := range addrs {
			localIPs[pfx.IP] = true
		}
	}

	v4Routes, v6Routes := false, false
	for _, r := range routes {
		// It's possible to advertise a route to one of the local
		// machine's local IPs. IP forwarding isn't required for this
		// to work, so we shouldn't warn for such exports.
		if r.IsSingleIP() && localIPs[r.IP] {
			continue
		}
		if r.IP.Is4() {
			v4Routes = true
		} else {
			v6Routes = true
		}
	}

	if v4Routes {
		out, err := ioutil.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil {
			// Try another way.
			out, err = exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
		}
		if err != nil {
			// Oh well, we tried. This is just for debugging.
			// We don't want false positives.
			// TODO: maybe we want a different warning for inability to check?
			return false
		}
		if strings.TrimSpace(string(out)) == "0" {
			return true
		}
	}
	if v6Routes {
		// Note: you might be wondering why we check only the state of
		// conf.all.forwarding, rather than per-interface forwarding
		// configuration. According to kernel documentation, it seems
		// that to actually forward packets, you need to enable
		// forwarding globally, and the per-interface forwarding
		// setting only alters other things such as how router
		// advertisements are handled. The kernel itself warns that
		// enabling forwarding per-interface and not globally will
		// probably not work, so I feel okay calling those configs
		// broken until we have proof otherwise.
		out, err := ioutil.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
		if err != nil {
			out, err = exec.Command("sysctl", "-n", "net.ipv6.conf.all.forwarding").Output()
		}
		if err != nil {
			// Oh well, we tried. This is just for debugging.
			// We don't want false positives.
			// TODO: maybe we want a different warning for inability to check?
			return false
		}
		if strings.TrimSpace(string(out)) == "0" {
			return true
		}
	}

	return false
}

func answerPing(logf logger.Logf, c *http.Client, pr *tailcfg.PingRequest) {
	if pr.URL == "" {
		logf("invalid PingRequest with no URL")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", pr.URL, nil)
	if err != nil {
		logf("http.NewRequestWithContext(%q): %v", pr.URL, err)
		return
	}
	if pr.Log {
		logf("answerPing: sending ping to %v ...", pr.URL)
	}
	t0 := time.Now()
	_, err = c.Do(req)
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		logf("answerPing error: %v to %v (after %v)", err, pr.URL, d)
	} else if pr.Log {
		logf("answerPing complete to %v (after %v)", pr.URL, d)
	}
}

func sleepAsRequested(ctx context.Context, logf logger.Logf, timeoutReset chan<- struct{}, d time.Duration) error {
	const maxSleep = 5 * time.Minute
	if d > maxSleep {
		logf("sleeping for %v, capped from server-requested %v ...", maxSleep, d)
		d = maxSleep
	} else {
		logf("sleeping for server-requested %v ...", d)
	}

	ticker := time.NewTicker(pollTimeout / 2)
	defer ticker.Stop()
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case <-ticker.C:
			select {
			case timeoutReset <- struct{}{}:
			case <-timer.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
