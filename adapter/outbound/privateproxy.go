package outbound

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"private_proxy/pkg/tunnel"
)

type PrivateProxyOption struct {
	BasicOption
	Name   string `proxy:"name"`
	Server string `proxy:"server"`
	Port   int    `proxy:"port"`
	PSK    string `proxy:"psk"`
	SNI    string `proxy:"sni,omitempty"`
	NodeID int    `proxy:"node_id,omitempty"`
	CAFile string `proxy:"ca_file,omitempty"`
	// SPKIPins contains base64 SHA-256 SubjectPublicKeyInfo digests.
	SPKIPins []string `proxy:"spki_pins,omitempty"`
	// Transport is tls-yamux by default. http2/http3 are reserved for V2
	// builds that register the corresponding transport adapter.
	Transport string `proxy:"transport,omitempty"`
	// SessionPool is the number of independent TLS/yamux sessions opened on
	// demand. More than one session limits cross-stream head-of-line blocking
	// on lossy long-distance TCP paths.
	SessionPool int `proxy:"session_pool,omitempty"`
}

type PrivateProxy struct {
	*Base
	option PrivateProxyOption
	addr   string

	mu         sync.RWMutex
	dialMu     sync.Mutex
	tunnels    []privateProxyTunnel
	dialTunnel privateProxyTunnelDialer
	next       atomic.Uint64
	closed     bool
}

type privateProxyTunnel interface {
	DialContext(context.Context, string) (net.Conn, error)
	Close() error
	IsClosed() bool
}

type privateProxyTunnelDialer func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error)

const (
	defaultPrivateProxySessionPool = 2
	maxPrivateProxySessionPool     = 4
)

func NewPrivateProxy(option PrivateProxyOption) (*PrivateProxy, error) {
	if option.Server == "" {
		return nil, fmt.Errorf("privateproxy: server required")
	}
	lowerPSK := strings.ToLower(option.PSK)
	if len(option.PSK) < 32 || strings.Contains(lowerPSK, "change-me") || strings.Contains(lowerPSK, "replace") {
		return nil, fmt.Errorf("privateproxy: psk must be at least 32 bytes and must not be a placeholder")
	}
	if option.Port == 0 {
		option.Port = 443
	}
	if option.SNI == "" {
		option.SNI = option.Server
	}
	if option.NodeID == 0 {
		option.NodeID = 1
	}
	if err := tunnel.ValidateSPKIPins(option.SPKIPins); err != nil {
		return nil, fmt.Errorf("privateproxy: %w", err)
	}
	if err := tunnel.ValidateTransportMode(option.Transport); err != nil {
		return nil, fmt.Errorf("privateproxy: %w", err)
	}
	if option.SessionPool == 0 {
		option.SessionPool = defaultPrivateProxySessionPool
	}
	if option.SessionPool < 1 || option.SessionPool > maxPrivateProxySessionPool {
		return nil, fmt.Errorf("privateproxy: session_pool must be between 1 and %d", maxPrivateProxySessionPool)
	}

	addr := net.JoinHostPort(option.Server, fmt.Sprintf("%d", option.Port))
	p := &PrivateProxy{
		Base: NewBase(BaseOption{
			Name: option.Name, Addr: addr,
			Type: C.Compatible, UDP: false,
		}),
		option: option, addr: addr,
		dialTunnel: func(ctx context.Context, entry tunnel.ServerEntry, psk string) (privateProxyTunnel, error) {
			return tunnel.DialTunnelContext(ctx, entry, psk)
		},
	}

	return p, nil
}

func (p *PrivateProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	t, err := p.getOrCreateTunnel(ctx)
	if err != nil {
		return nil, fmt.Errorf("privateproxy tunnel: %w", err)
	}

	dest := metadata.RemoteAddress()
	conn, err := t.DialContext(ctx, dest)
	if err != nil && t.IsClosed() && ctx.Err() == nil {
		// A dead pooled session should not poison subsequent streams. Remove it
		// and retry once on another (or newly created) on-demand session.
		p.removeTunnel(t)
		if replacement, replacementErr := p.getOrCreateTunnel(ctx); replacementErr == nil {
			conn, err = replacement.DialContext(ctx, dest)
		}
	}
	if err != nil {
		log.Errorln("privateproxy: dial %s: %v", dest, err)
		return nil, fmt.Errorf("dial %s: %w", dest, err)
	}
	return NewConn(conn, p), nil
}

func (p *PrivateProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, fmt.Errorf("privateproxy: UDP not supported")
}

func (p *PrivateProxy) readyTunnel() privateProxyTunnel {
	return p.selectTunnel(true)
}

func (p *PrivateProxy) liveTunnel() privateProxyTunnel {
	return p.selectTunnel(false)
}

func (p *PrivateProxy) selectTunnel(requireFullPool bool) privateProxyTunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || len(p.tunnels) == 0 {
		return nil
	}

	live := 0
	for _, t := range p.tunnels {
		if t == nil || t.IsClosed() {
			continue
		}
		live++
	}
	if live == 0 || (requireFullPool && live < p.option.SessionPool) {
		return nil
	}

	start := int(p.next.Add(1)-1) % len(p.tunnels)
	for offset := range len(p.tunnels) {
		t := p.tunnels[(start+offset)%len(p.tunnels)]
		if t != nil && !t.IsClosed() {
			return t
		}
	}
	return nil
}

func (p *PrivateProxy) getOrCreateTunnel(ctx context.Context) (privateProxyTunnel, error) {
	if current := p.readyTunnel(); current != nil {
		return current, nil
	}

	p.dialMu.Lock()
	defer p.dialMu.Unlock()
	if current := p.readyTunnel(); current != nil {
		return current, nil
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	live := p.tunnels[:0]
	for _, current := range p.tunnels {
		if current != nil && !current.IsClosed() {
			live = append(live, current)
		}
	}
	p.tunnels = live
	poolIndex := len(p.tunnels) + 1
	p.mu.Unlock()

	entry := tunnel.ServerEntry{
		Name: p.option.Name, Address: p.addr, SNI: p.option.SNI,
		NodeID: uint32(p.option.NodeID), Weight: 10,
		CAFile: p.option.CAFile, SPKIPins: p.option.SPKIPins, Transport: p.option.Transport,
	}
	log.Infoln("privateproxy: connecting to %s on demand (session %d/%d)", p.addr, poolIndex, p.option.SessionPool)
	t, err := p.dialTunnel(ctx, entry, p.option.PSK)
	if err != nil {
		if ctx.Err() == nil {
			if fallback := p.liveTunnel(); fallback != nil {
				log.Warnln("privateproxy: session pool refill failed for %s; reusing a healthy session: %v", p.addr, err)
				return fallback, nil
			}
		}
		return nil, err
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = t.Close()
		return nil, net.ErrClosed
	}
	p.tunnels = append(p.tunnels, t)
	p.mu.Unlock()
	log.Infoln("privateproxy: tunnel to %s ready (session %d/%d)", p.addr, poolIndex, p.option.SessionPool)
	return t, nil
}

func (p *PrivateProxy) removeTunnel(target privateProxyTunnel) {
	p.mu.Lock()
	live := p.tunnels[:0]
	for _, current := range p.tunnels {
		if current != target {
			live = append(live, current)
		}
	}
	p.tunnels = live
	p.mu.Unlock()
	_ = target.Close()
}

func (p *PrivateProxy) SupportUDP() bool { return false }

func (p *PrivateProxy) Alive() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, current := range p.tunnels {
		if current != nil && !current.IsClosed() {
			return true
		}
	}
	return false
}

func (p *PrivateProxy) Close() error {
	p.dialMu.Lock()
	defer p.dialMu.Unlock()
	p.mu.Lock()
	p.closed = true
	tunnels := p.tunnels
	p.tunnels = nil
	p.mu.Unlock()
	var firstErr error
	for _, current := range tunnels {
		if current != nil {
			if err := current.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
