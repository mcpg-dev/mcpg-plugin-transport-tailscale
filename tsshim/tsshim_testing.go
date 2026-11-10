//go:build mcpgts_testing

// Test-only exports: an in-process Tailscale control server with DERP and
// STUN on 127.0.0.1, and an outbound dial, so the plugin's tests join real
// nodes to a real tailnet with no account and no network. Never in a
// shipped archive.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http/httptest"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

var (
	controlMu sync.Mutex
	control   *testcontrol.Server
	tb        *fakeTB
)

// testControlConfig is the JSON mcpgts_test_control_start takes.
type testControlConfig struct {
	// RequireAuthKey, when set, is the only auth key the control accepts.
	RequireAuthKey string `json:"require_auth_key"`
	// AppCaps are granted to every peer, as tailnet policy grants would.
	AppCaps map[string][]json.RawMessage `json:"app_caps"`
	// MagicDNSDomain names the tailnet's DNS suffix.
	MagicDNSDomain string `json:"magic_dns_domain"`
}

// mcpgts_test_control_start starts the control server. On success *url
// holds its URL.
//
//export mcpgts_test_control_start
func mcpgts_test_control_start(configJSON *C.char, urlOut **C.char, errOut **C.char) C.int {
	controlMu.Lock()
	defer controlMu.Unlock()
	if control != nil {
		setErr(errOut, errors.New("a test control is already running"))
		return -1
	}
	var cfg testControlConfig
	if err := json.Unmarshal([]byte(C.GoString(configJSON)), &cfg); err != nil {
		setErr(errOut, fmt.Errorf("test control config: %w", err))
		return -1
	}
	netns.SetEnabled(false)
	tb = &fakeTB{}
	derpMap := integration.RunDERPAndSTUN(tb, logger.Discard, "127.0.0.1")
	domain := cfg.MagicDNSDomain
	if domain == "" {
		domain = "tail-test.ts.net"
	}
	control = &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: domain,
		RequireAuthKey: cfg.RequireAuthKey,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	if len(cfg.AppCaps) > 0 {
		caps := tailcfg.PeerCapMap{}
		for name, values := range cfg.AppCaps {
			for _, v := range values {
				caps[tailcfg.PeerCapability(name)] = append(caps[tailcfg.PeerCapability(name)], tailcfg.RawMessage(v))
			}
		}
		control.SetGlobalAppCaps(caps)
	}
	setStr(urlOut, control.HTTPTestServer.URL)
	return 0
}

// mcpgts_test_control_stop stops the control server and its DERP and STUN.
//
//export mcpgts_test_control_stop
func mcpgts_test_control_stop() {
	controlMu.Lock()
	defer controlMu.Unlock()
	if control == nil {
		return
	}
	control.HTTPTestServer.Close()
	tb.shutdown()
	control = nil
	netns.SetEnabled(true)
}

// mcpgts_dial connects the node to addr (`ip:port` on the tailnet). On
// success *fd is the caller's end of a socketpair.
//
//export mcpgts_dial
func mcpgts_dial(h C.int64_t, addr *C.char, fdOut *C.int, errOut **C.char) C.int {
	n := lookup(nodes, h)
	if n == nil {
		setErr(errOut, errors.New("unknown node"))
		return -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := n.srv.Dial(ctx, "tcp", C.GoString(addr))
	if err != nil {
		setErr(errOut, err)
		return -1
	}
	fds, err := socketpair()
	if err != nil {
		conn.Close()
		setErr(errOut, err)
		return -1
	}
	local := os.NewFile(uintptr(fds[0]), "tsshim-dial")
	peer, err := net.FileConn(local)
	local.Close()
	if err != nil {
		conn.Close()
		syscall.Close(fds[1])
		setErr(errOut, err)
		return -1
	}
	go pump(conn, peer)
	*fdOut = C.int(fds[1])
	return 0
}

// fakeTB satisfies testing.TB for the integration helpers outside `go test`.
type fakeTB struct {
	*testing.T
	mu       sync.Mutex
	cleanups []func()
}

func (t *fakeTB) Cleanup(f func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cleanups = append(t.cleanups, f)
}

func (t *fakeTB) shutdown() {
	t.mu.Lock()
	cleanups := t.cleanups
	t.cleanups = nil
	t.mu.Unlock()
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
}

func (t *fakeTB) Error(args ...any)                 { log.Print(args...) }
func (t *fakeTB) Errorf(format string, args ...any) { log.Printf(format, args...) }
func (t *fakeTB) Fail()                             {}
func (t *fakeTB) FailNow()                          { log.Fatal("test control: FailNow") }
func (t *fakeTB) Failed() bool                      { return false }
func (t *fakeTB) Fatal(args ...any)                 { log.Fatal(args...) }
func (t *fakeTB) Fatalf(format string, args ...any) { log.Fatalf(format, args...) }
func (t *fakeTB) Helper()                           {}
func (t *fakeTB) Log(args ...any)                   {}
func (t *fakeTB) Logf(format string, args ...any)   {}
func (t *fakeTB) Name() string                      { return "mcpgts" }
func (t *fakeTB) Setenv(key, value string)          { panic("not supported") }
func (t *fakeTB) Skip(args ...any)                  {}
func (t *fakeTB) SkipNow()                          {}
func (t *fakeTB) Skipf(format string, args ...any)  {}
func (t *fakeTB) Skipped() bool                     { return false }
func (t *fakeTB) TempDir() string {
	dir, err := os.MkdirTemp("", "mcpgts")
	if err != nil {
		log.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
