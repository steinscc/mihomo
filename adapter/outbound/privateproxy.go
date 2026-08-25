package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
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
	// demand. It is a maximum connection count; sessions are added only when
	// every live session reaches MaxStreamsPerSession.
	SessionPool int `proxy:"session_pool,omitempty"`
	// MaxStreamsPerSession is the soft admission threshold used to decide when
	// another underlying session should be opened. Once the pool is full, the
	// least-loaded session remains usable beyond this threshold.
	MaxStreamsPerSession int `proxy:"max_streams_per_session,omitempty"`
}

type privateProxyTunnelState struct {
	tunnel  privateProxyTunnel
	pending atomic.Int64
}

type PrivateProxy struct {
	*Base
	option PrivateProxyOption
	addr   string

	mu         sync.RWMutex
	dialMu     sync.Mutex
	tunnels    []*privateProxyTunnelState
	dialTunnel privateProxyTunnelDialer
	next       atomic.Uint64
	closed     bool
}

type privateProxyTunnel interface {
	DialContext(context.Context, string) (net.Conn, error)
	Close() error
	IsClosed() bool
	NumStreams() int
}

type privateProxyTunnelReservation struct {
	state *privateProxyTunnelState
	once  sync.Once
}

func (r *privateProxyTunnelReservation) tunnel() privateProxyTunnel {
	if r == nil || r.state == nil {
		return nil
	}
	return r.state.tunnel
}

func (r *privateProxyTunnelReservation) release() {
	if r == nil || r.state == nil {
		return
	}
	r.once.Do(func() { r.state.pending.Add(-1) })
}

type privateProxyTunnelDialer func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error)

const (
	defaultPrivateProxySessionPool = 8
	maxPrivateProxySessionPool     = 16
	defaultMaxStreamsPerSession    = 8
	maxMaxStreamsPerSession        = 64
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
	if option.MaxStreamsPerSession == 0 {
		option.MaxStreamsPerSession = defaultMaxStreamsPerSession
	}
	if option.MaxStreamsPerSession < 1 || option.MaxStreamsPerSession > maxMaxStreamsPerSession {
		return nil, fmt.Errorf("privateproxy: max_streams_per_session must be between 1 and %d", maxMaxStreamsPerSession)
	}

	addr := net.JoinHostPort(option.Server, fmt.Sprintf("%d", option.Port))
	p := &PrivateProxy{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Compatible,
			ProviderName: option.ProviderName,
			UDP:          false,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: option, addr: addr,
		dialTunnel: func(ctx context.Context, entry tunnel.ServerEntry, psk string) (privateProxyTunnel, error) {
			return tunnel.DialTunnelContext(ctx, entry, psk)
		},
	}

	// The control-plane connection is an outbound connection too. Build it
	// through Mihomo's configured dialer so interface binding, routing marks,
	// IP-version preference, TFO/MPTCP, proxy chaining, and proxy DNS all apply
	// before the PrivateProxy TLS handshake starts.
	dialOptions := append([]dialer.Option(nil), p.DialOptions()...)
	dialOptions = append(dialOptions, dialer.WithResolver(resolver.ProxyServerHostResolver))
	p.dialer = option.NewDialer(dialOptions)

	return p, nil
}

func (p *PrivateProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	reservation, err := p.reserveTunnel(ctx)
	if err != nil {
		return nil, fmt.Errorf("privateproxy tunnel: %w", err)
	}
	t := reservation.tunnel()
	defer reservation.release()
	if metadata == nil || t == nil {
		return nil, errors.New("privateproxy: tunnel or metadata is nil")
	}

	dest := metadata.RemoteAddress()
	conn, err := t.DialContext(ctx, dest)
	reservation.release()
	if err != nil && shouldRetryPrivateProxyDial(t, err) && ctx.Err() == nil {
		// A dead pooled session should not poison subsequent streams. Remove it
		// and retry once on another (or newly created) on-demand session.
		p.removeTunnel(t)
		if replacementReservation, replacementErr := p.reserveTunnel(ctx); replacementErr == nil {
			replacement := replacementReservation.tunnel()
			conn, err = replacement.DialContext(ctx, dest)
			replacementReservation.release()
			if err != nil && shouldRetryPrivateProxyDial(replacement, err) {
				// Do not leave a replacement that failed during the control
				// plane handshake in the pool. This is cleanup only; the
				// request still gets at most one retry.
				p.removeTunnel(replacement)
			}
		}
	}
	if err != nil {
		log.Errorln("privateproxy: dial %s: %v", dest, err)
		return nil, fmt.Errorf("dial %s: %w", dest, err)
	}
	return NewConn(conn, p), nil
}

func shouldRetryPrivateProxyDial(t privateProxyTunnel, err error) bool {
	return errors.Is(err, tunnel.ErrControlPlaneFailure) || (t != nil && t.IsClosed())
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
	for _, state := range p.tunnels {
		if state == nil || state.tunnel == nil || state.tunnel.IsClosed() {
			continue
		}
		live++
	}
	if live == 0 || (requireFullPool && live < p.option.SessionPool) {
		return nil
	}

	minStreams := int(^uint(0) >> 1)
	var leastLoaded [maxPrivateProxySessionPool]privateProxyTunnel
	tieCount := 0
	for _, state := range p.tunnels {
		if state == nil || state.tunnel == nil || state.tunnel.IsClosed() {
			continue
		}
		streams := state.tunnel.NumStreams() + int(state.pending.Load())
		if streams < minStreams {
			minStreams = streams
			tieCount = 1
			leastLoaded[0] = state.tunnel
		} else if streams == minStreams {
			tieCount++
			leastLoaded[tieCount-1] = state.tunnel
		}
	}
	if tieCount == 0 {
		return nil
	}

	// Keep round-robin fairness among tunnels with the same load. Using the
	// atomic ticket over the tied set avoids repeatedly selecting the first
	// minimum when the least-loaded tunnels are not adjacent in the pool.
	target := int((p.next.Add(1) - 1) % uint64(tieCount))
	return leastLoaded[target]
}

func (p *PrivateProxy) getOrCreateTunnel(ctx context.Context) (privateProxyTunnel, error) {
	reservation, err := p.reserveTunnel(ctx)
	if err != nil {
		return nil, err
	}
	t := reservation.tunnel()
	reservation.release()
	return t, nil
}

// reserveTunnel selects a live session and reserves one pending stream. A new
// session is opened synchronously only when every live session has reached the
// configured threshold and the pool still has room. Existing capacity always
// wins over a refill dial, and an existing live session is returned if a refill
// fails.
func (p *PrivateProxy) reserveTunnel(ctx context.Context) (*privateProxyTunnelReservation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		p.mu.Lock()
		p.pruneClosedLocked()
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		best, live, bestLoad := p.bestSessionLocked()
		if best != nil && (bestLoad < p.option.MaxStreamsPerSession || live >= p.option.SessionPool) {
			best.pending.Add(1)
			p.mu.Unlock()
			return &privateProxyTunnelReservation{state: best}, nil
		}
		if live >= p.option.SessionPool {
			// Defensive fallback for a zero/invalid threshold; normal validation
			// makes this branch equivalent to the soft-degrade condition above.
			if best != nil {
				best.pending.Add(1)
				p.mu.Unlock()
				return &privateProxyTunnelReservation{state: best}, nil
			}
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		p.mu.Unlock()

		// Serialize pool growth, but do not make concurrent requests wait behind
		// an in-progress refill when an existing live session can still serve
		// them. The caller that wins the lock performs the one synchronous dial;
		// other callers reserve the least-loaded live session immediately.
		if !p.dialMu.TryLock() {
			p.mu.Lock()
			p.pruneClosedLocked()
			best, _, _ = p.bestSessionLocked()
			if best != nil && !p.closed {
				best.pending.Add(1)
				p.mu.Unlock()
				return &privateProxyTunnelReservation{state: best}, nil
			}
			closed := p.closed
			p.mu.Unlock()
			if closed {
				return nil, net.ErrClosed
			}
			p.dialMu.Lock()
		}
		// Re-check capacity after acquiring the lock: another caller may have
		// opened a session while this caller waited.
		p.mu.Lock()
		p.pruneClosedLocked()
		if p.closed {
			p.mu.Unlock()
			p.dialMu.Unlock()
			return nil, net.ErrClosed
		}
		best, live, bestLoad = p.bestSessionLocked()
		if best != nil && (bestLoad < p.option.MaxStreamsPerSession || live >= p.option.SessionPool) {
			best.pending.Add(1)
			p.mu.Unlock()
			p.dialMu.Unlock()
			return &privateProxyTunnelReservation{state: best}, nil
		}
		if live >= p.option.SessionPool {
			if best != nil {
				best.pending.Add(1)
				p.mu.Unlock()
				p.dialMu.Unlock()
				return &privateProxyTunnelReservation{state: best}, nil
			}
			p.mu.Unlock()
			p.dialMu.Unlock()
			return nil, net.ErrClosed
		}
		poolIndex := live + 1
		p.mu.Unlock()

		entry := p.serverEntry()
		log.Infoln("privateproxy: connecting to %s on demand (session %d/%d)", p.addr, poolIndex, p.option.SessionPool)
		t, err := p.dialTunnel(ctx, entry, p.option.PSK)
		if err == nil && t == nil {
			err = errors.New("privateproxy: tunnel dialer returned a nil session")
		}
		if err == nil {
			p.mu.Lock()
			closed := p.closed
			if !closed {
				p.tunnels = append(p.tunnels, &privateProxyTunnelState{tunnel: t})
			}
			p.mu.Unlock()
			if closed {
				p.dialMu.Unlock()
				_ = t.Close()
				return nil, net.ErrClosed
			}
			log.Infoln("privateproxy: tunnel to %s ready (session %d/%d)", p.addr, poolIndex, p.option.SessionPool)
			p.dialMu.Unlock()
			// Loop once so the newly created session receives the reservation.
			continue
		}
		p.dialMu.Unlock()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// A failed refill must not make an already usable partial pool
		// unavailable. Reserve the least-loaded live session immediately.
		p.mu.Lock()
		p.pruneClosedLocked()
		best, _, _ = p.bestSessionLocked()
		if best != nil && !p.closed {
			best.pending.Add(1)
			p.mu.Unlock()
			log.Warnln("privateproxy: session pool refill failed for %s; reusing a healthy session: %v", p.addr, err)
			return &privateProxyTunnelReservation{state: best}, nil
		}
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		return nil, err
	}
}

func (p *PrivateProxy) bestSessionLocked() (best *privateProxyTunnelState, live, bestLoad int) {
	bestLoad = int(^uint(0) >> 1)
	for _, state := range p.tunnels {
		if state == nil || state.tunnel == nil || state.tunnel.IsClosed() {
			continue
		}
		live++
		load := state.tunnel.NumStreams() + int(state.pending.Load())
		if best == nil || load < bestLoad {
			best = state
			bestLoad = load
		}
	}
	return best, live, bestLoad
}

func (p *PrivateProxy) pruneClosedLocked() {
	if len(p.tunnels) == 0 {
		return
	}
	live := p.tunnels[:0]
	for _, state := range p.tunnels {
		if state != nil && state.tunnel != nil && !state.tunnel.IsClosed() {
			live = append(live, state)
		}
	}
	p.tunnels = live
}

func (p *PrivateProxy) serverEntry() tunnel.ServerEntry {
	entry := tunnel.ServerEntry{
		Name: p.option.Name, Address: p.addr, SNI: p.option.SNI,
		NodeID: uint32(p.option.NodeID), Weight: 10,
		CAFile: p.option.CAFile, SPKIPins: p.option.SPKIPins, Transport: p.option.Transport,
	}
	if p.dialer != nil {
		entry.RawDialContext = p.dialer.DialContext
	}
	return entry
}

func (p *PrivateProxy) removeTunnel(target privateProxyTunnel) {
	p.mu.Lock()
	live := p.tunnels[:0]
	var removed []privateProxyTunnel
	for _, state := range p.tunnels {
		if state == nil || !samePrivateProxyTunnel(state.tunnel, target) {
			live = append(live, state)
		} else if state.tunnel != nil {
			removed = append(removed, state.tunnel)
		}
	}
	p.tunnels = live
	p.mu.Unlock()
	if target != nil {
		removed = append(removed, target)
	}
	for _, current := range removed {
		_ = current.Close()
	}
}

func samePrivateProxyTunnel(a, b privateProxyTunnel) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ta, tb := reflect.TypeOf(a), reflect.TypeOf(b)
	if ta != tb || !ta.Comparable() {
		return false
	}
	return a == b
}

func (p *PrivateProxy) SupportUDP() bool { return false }

func (p *PrivateProxy) Alive() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, state := range p.tunnels {
		if state != nil && state.tunnel != nil && !state.tunnel.IsClosed() {
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
	for _, state := range tunnels {
		if state != nil && state.tunnel != nil {
			if err := state.tunnel.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
