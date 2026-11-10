// Command tsshim is a C archive that embeds a Tailscale node (tsnet) in the
// dev.mcpg.transport.tailscale plugin.
//
// Every exported function is safe to call from any thread. Strings the shim
// returns through `char**` are allocated with malloc and freed by the caller
// with mcpgts_free. A connection crosses to the caller as one end of a
// socketpair; the shim copies bytes between it and the tailnet connection.
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef void (*mcpgts_log_fn)(int level, const char *message);

static void mcpgts_call_log(mcpgts_log_fn fn, int level, const char *message) {
	if (fn != NULL) {
		fn(level, message);
	}
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/tsnet"
)

func main() {}

// Log levels passed to the log callback.
const (
	logDebug = 0
	logInfo  = 1
)

var logFn atomic.Pointer[C.mcpgts_log_fn]

func logAt(level int) func(format string, args ...any) {
	return func(format string, args ...any) {
		fn := logFn.Load()
		if fn == nil {
			return
		}
		msg := C.CString(strings.TrimRight(fmt.Sprintf(format, args...), "\n"))
		defer C.free(unsafe.Pointer(msg))
		C.mcpgts_call_log(*fn, C.int(level), msg)
	}
}

// mcpgts_set_log routes every node's log lines to fn: level 0 is the
// backend's debug output, level 1 the lines meant for the operator (login
// URLs, state changes). NULL stops logging.
//
//export mcpgts_set_log
func mcpgts_set_log(fn C.mcpgts_log_fn) {
	if fn == nil {
		logFn.Store(nil)
		return
	}
	logFn.Store(&fn)
}

type node struct {
	srv *tsnet.Server
	lc  *local.Client
}

type listener struct {
	ln     net.Listener
	funnel bool
}

var (
	mu        sync.Mutex
	nextID    int64
	nodes     = map[int64]*node{}
	listeners = map[int64]*listener{}
)

func register[T any](table map[int64]*T, v *T) int64 {
	mu.Lock()
	defer mu.Unlock()
	nextID++
	table[nextID] = v
	return nextID
}

func lookup[T any](table map[int64]*T, id C.int64_t) *T {
	mu.Lock()
	defer mu.Unlock()
	return table[int64(id)]
}

func setErr(out **C.char, err error) {
	if out != nil && err != nil {
		*out = C.CString(err.Error())
	}
}

func setStr(out **C.char, s string) {
	if out != nil {
		*out = C.CString(s)
	}
}

// nodeConfig is the JSON the plugin passes to mcpgts_new.
type nodeConfig struct {
	Dir           string   `json:"dir"`
	Hostname      string   `json:"hostname"`
	AuthKey       string   `json:"auth_key"`
	ClientSecret  string   `json:"client_secret"`
	ClientID      string   `json:"client_id"`
	IDToken       string   `json:"id_token"`
	Audience      string   `json:"audience"`
	ControlURL    string   `json:"control_url"`
	Ephemeral     bool     `json:"ephemeral"`
	AdvertiseTags []string `json:"advertise_tags"`
	UploadLogs    bool     `json:"upload_logs"`
	Port          uint16   `json:"port"`
}

var noLogsOnce sync.Once

// mcpgts_new creates a node from a JSON nodeConfig. It does not connect;
// mcpgts_up does. Returns the node handle, or 0 with *err set.
//
//export mcpgts_new
func mcpgts_new(configJSON *C.char, errOut **C.char) C.int64_t {
	var cfg nodeConfig
	if err := json.Unmarshal([]byte(C.GoString(configJSON)), &cfg); err != nil {
		setErr(errOut, fmt.Errorf("node config: %w", err))
		return 0
	}
	if !cfg.UploadLogs {
		// Process-wide: once any node in the gateway runs without upload,
		// none uploads.
		noLogsOnce.Do(func() { envknob.Setenv("TS_NO_LOGS_NO_SUPPORT", "true") })
	}
	srv := &tsnet.Server{
		Dir:           cfg.Dir,
		Hostname:      cfg.Hostname,
		AuthKey:       cfg.AuthKey,
		ClientSecret:  cfg.ClientSecret,
		ClientID:      cfg.ClientID,
		IDToken:       cfg.IDToken,
		Audience:      cfg.Audience,
		ControlURL:    cfg.ControlURL,
		Ephemeral:     cfg.Ephemeral,
		AdvertiseTags: cfg.AdvertiseTags,
		Port:          cfg.Port,
		Logf:          logAt(logDebug),
		UserLogf:      logAt(logInfo),
	}
	return C.int64_t(register(nodes, &node{srv: srv}))
}

// nodeStatus is what mcpgts_up reports.
type nodeStatus struct {
	DNSName        string   `json:"dns_name"`
	IPs            []string `json:"ips"`
	Tailnet        string   `json:"tailnet"`
	MagicDNSSuffix string   `json:"magic_dns_suffix"`
	CertDomains    []string `json:"cert_domains"`
	FunnelCapable  bool     `json:"funnel_capable"`
}

// mcpgts_up connects the node and waits until it is running, at most
// timeout_ms. On success *status holds a JSON nodeStatus.
//
//export mcpgts_up
func mcpgts_up(h C.int64_t, timeoutMs C.int, statusOut **C.char, errOut **C.char) C.int {
	n := lookup(nodes, h)
	if n == nil {
		setErr(errOut, errors.New("unknown node"))
		return -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	st, err := n.srv.Up(ctx)
	if err != nil {
		setErr(errOut, err)
		return -1
	}
	lc, err := n.srv.LocalClient()
	if err != nil {
		setErr(errOut, err)
		return -1
	}
	mu.Lock()
	n.lc = lc
	mu.Unlock()
	out := nodeStatus{CertDomains: n.srv.CertDomains()}
	if st.Self != nil {
		out.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
		for _, ip := range st.Self.TailscaleIPs {
			out.IPs = append(out.IPs, ip.String())
		}
		out.FunnelCapable = st.Self.HasCap("funnel")
	}
	if st.CurrentTailnet != nil {
		out.Tailnet = st.CurrentTailnet.Name
		out.MagicDNSSuffix = st.CurrentTailnet.MagicDNSSuffix
	}
	b, _ := json.Marshal(out)
	setStr(statusOut, string(b))
	return 0
}

// mcpgts_listen opens a listener on the node: mode "tcp" (plain, tailnet
// only), "tls" (HTTPS with the node's tailnet certificate, tailnet only) or
// "funnel" (HTTPS from the public internet, not the tailnet). Returns the
// listener handle, or 0 with *err set.
//
//export mcpgts_listen
func mcpgts_listen(h C.int64_t, mode *C.char, port C.int, errOut **C.char) C.int64_t {
	n := lookup(nodes, h)
	if n == nil {
		setErr(errOut, errors.New("unknown node"))
		return 0
	}
	addr := fmt.Sprintf(":%d", int(port))
	var (
		ln     net.Listener
		err    error
		funnel bool
	)
	switch m := C.GoString(mode); m {
	case "tcp":
		ln, err = n.srv.Listen("tcp", addr)
	case "tls":
		if len(n.srv.CertDomains()) == 0 {
			err = errors.New("the tailnet issues no HTTPS certificates: turn on MagicDNS and HTTPS in the Tailscale admin console, or listen with mode http")
		} else {
			ln, err = n.srv.ListenTLS("tcp", addr)
		}
	case "funnel":
		funnel = true
		ln, err = n.srv.ListenFunnel("tcp", addr, tsnet.FunnelOnly())
	default:
		err = fmt.Errorf("unknown listen mode %q", m)
	}
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	return C.int64_t(register(listeners, &listener{ln: ln, funnel: funnel}))
}

// mcpgts_accept waits for the next connection. Returns 0 with *fd set to
// the caller's end of a socketpair and *remote to the peer address, 1 once
// the listener is closed, or -1 with *err set.
//
//export mcpgts_accept
func mcpgts_accept(l C.int64_t, fdOut *C.int, remoteOut **C.char, errOut **C.char) C.int {
	lis := lookup(listeners, l)
	if lis == nil {
		return 1
	}
	conn, err := lis.ln.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return 1
		}
		setErr(errOut, err)
		return -1
	}
	fds, err := socketpair()
	if err != nil {
		conn.Close()
		setErr(errOut, err)
		return -1
	}
	local := os.NewFile(uintptr(fds[0]), "tsshim")
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
	setStr(remoteOut, conn.RemoteAddr().String())
	return 0
}

type closeWriter interface{ CloseWrite() error }

// pump copies both ways until both directions end, passing a half-close on.
func pump(a, b net.Conn) {
	var wg sync.WaitGroup
	one := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go one(a, b)
	go one(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// socketpair returns a close-on-exec AF_UNIX stream pair.
func socketpair() ([2]int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fds, err
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	return fds, nil
}

// peerIdentity is what mcpgts_whois reports for a tailnet peer.
type peerIdentity struct {
	Login       string                     `json:"login"`
	DisplayName string                     `json:"display_name"`
	UserID      int64                      `json:"user_id"`
	NodeName    string                     `json:"node_name"`
	NodeID      string                     `json:"node_id"`
	Tags        []string                   `json:"tags"`
	Caps        map[string]json.RawMessage `json:"caps"`
}

// mcpgts_whois asks the node who owns the tailnet peer at remote
// (`ip:port`). On success *out holds a JSON peerIdentity.
//
//export mcpgts_whois
func mcpgts_whois(h C.int64_t, remote *C.char, out **C.char, errOut **C.char) C.int {
	n := lookup(nodes, h)
	if n == nil {
		setErr(errOut, errors.New("unknown node"))
		return -1
	}
	mu.Lock()
	lc := n.lc
	mu.Unlock()
	if lc == nil {
		setErr(errOut, errors.New("the node is not up"))
		return -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := lc.WhoIs(ctx, C.GoString(remote))
	if err != nil {
		setErr(errOut, err)
		return -1
	}
	id := peerIdentity{Caps: map[string]json.RawMessage{}}
	if w.UserProfile != nil {
		id.Login = w.UserProfile.LoginName
		id.DisplayName = w.UserProfile.DisplayName
		id.UserID = int64(w.UserProfile.ID)
	}
	if w.Node != nil {
		id.NodeName = strings.TrimSuffix(w.Node.Name, ".")
		id.NodeID = string(w.Node.StableID)
		id.Tags = w.Node.Tags
	}
	for capability, values := range w.CapMap {
		b, err := json.Marshal(values)
		if err == nil {
			id.Caps[string(capability)] = b
		}
	}
	b, _ := json.Marshal(id)
	setStr(out, string(b))
	return 0
}

// mcpgts_close_listener stops a listener; a waiting mcpgts_accept returns 1.
//
//export mcpgts_close_listener
func mcpgts_close_listener(l C.int64_t) {
	mu.Lock()
	lis := listeners[int64(l)]
	delete(listeners, int64(l))
	mu.Unlock()
	if lis != nil {
		lis.ln.Close()
	}
}

// mcpgts_close shuts the node down. An ephemeral node leaves the tailnet.
//
//export mcpgts_close
func mcpgts_close(h C.int64_t) {
	mu.Lock()
	n := nodes[int64(h)]
	delete(nodes, int64(h))
	mu.Unlock()
	if n != nil {
		n.srv.Close()
	}
}

// mcpgts_free frees a string the shim returned.
//
//export mcpgts_free
func mcpgts_free(p *C.char) {
	C.free(unsafe.Pointer(p))
}
