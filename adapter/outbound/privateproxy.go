package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	// Transport is tls-yamux by default. http3 selects the V2 QUIC adapter;
	// http2 remains reserved.
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
	tunnel    privateProxyTunnel
	pending   atomic.Int64
	active    atomic.Int64
	retired   bool
	closeOnce sync.Once
	closeErr  error
}

func (s *privateProxyTunnelState) close() error {
	if s == nil || s.tunnel == nil {
		return nil
	}
	s.closeOnce.Do(func() { s.closeErr = s.tunnel.Close() })
	return s.closeErr
}

type privateProxyConn struct {
	C.Conn
	closeFunc func()
	closeOnce sync.Once
}

func (c *privateProxyConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(c.closeFunc)
	return err
}

func (c *privateProxyConn) AddRef(ref any) {
	if conn, ok := c.Conn.(AddRef); ok {
		conn.AddRef(ref)
	}
}

func (c *privateProxyConn) ReaderReplaceable() bool { return true }
func (c *privateProxyConn) WriterReplaceable() bool { return true }
func (c *privateProxyConn) Upstream() any           { return c.Conn }

type privateProxyPacketConn struct {
	C.PacketConn
	closeFunc func()
	closeOnce sync.Once
}

var (
	_ C.Conn       = (*privateProxyConn)(nil)
	_ C.PacketConn = (*privateProxyPacketConn)(nil)
	_ AddRef       = (*privateProxyConn)(nil)
	_ AddRef       = (*privateProxyPacketConn)(nil)
)

func (c *privateProxyPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.closeOnce.Do(c.closeFunc)
	return err
}

func (c *privateProxyPacketConn) AddRef(ref any) {
	if conn, ok := c.PacketConn.(AddRef); ok {
		conn.AddRef(ref)
	}
}

func (c *privateProxyPacketConn) ReaderReplaceable() bool { return true }
func (c *privateProxyPacketConn) WriterReplaceable() bool { return true }
func (c *privateProxyPacketConn) Upstream() any           { return c.PacketConn }

type PrivateProxy struct {
	*Base
	option PrivateProxyOption
	addr   string

	mu         sync.RWMutex
	dialMu     sync.Mutex
	tunnels    []*privateProxyTunnelState
	dialTunnel privateProxyTunnelDialer
	refillFail atomic.Uint32
	refillAt   atomic.Int64
	closed     bool
}

type privateProxyTunnel interface {
	DialContext(context.Context, string) (net.Conn, error)
	ListenPacketContext(context.Context) (net.PacketConn, error)
	Close() error
	IsClosed() bool
	NumStreams() int
}

type privateProxyTunnelReservation struct {
	owner    *PrivateProxy
	state    *privateProxyTunnelState
	mu       sync.Mutex
	active   bool
	released bool
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
	r.mu.Lock()
	if r.released {
		r.mu.Unlock()
		return
	}
	if r.active {
		r.state.active.Add(-1)
	} else {
		r.state.pending.Add(-1)
	}
	r.released = true
	r.mu.Unlock()
	if r.owner != nil {
		r.owner.closeRetiredIfDrained(r.state)
	}
}

// activate converts a pending reservation into an active stream. The active
// count is incremented before pending is decremented so a retired tunnel
// cannot be closed in the gap between the two state changes.
func (r *privateProxyTunnelReservation) activate() bool {
	if r == nil || r.state == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.active {
		return false
	}
	r.state.active.Add(1)
	r.state.pending.Add(-1)
	r.active = true
	return true
}

type privateProxyTunnelDialer func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error)

const (
	defaultPrivateProxySessionPool = 8
	maxPrivateProxySessionPool     = 16
	defaultMaxStreamsPerSession    = 8
	maxMaxStreamsPerSession        = 64
	privateProxyRefillBaseDelay    = 500 * time.Millisecond
	privateProxyRefillMaxDelay     = 30 * time.Second
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
	udpEnabled := strings.EqualFold(strings.TrimSpace(option.Transport), "http3")
	p := &PrivateProxy{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Compatible,
			ProviderName: option.ProviderName,
			UDP:          udpEnabled,
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
	if metadata == nil || t == nil {
		reservation.release()
		return nil, errors.New("privateproxy: tunnel or metadata is nil")
	}

	dest := metadata.RemoteAddress()
	conn, err := p.dialReserved(ctx, dest, reservation)
	if err != nil && p.finishFailedReservation(ctx, reservation, err) {
		// A failed pooled session should not receive new streams. Retire it and
		// retry once on another (or newly created) on-demand session while any
		// established sibling streams drain.
		if replacementReservation, replacementErr := p.reserveTunnel(ctx); replacementErr == nil {
			conn, err = p.dialReserved(ctx, dest, replacementReservation)
			if err != nil {
				// Do not leave a replacement that failed during the control
				// plane handshake in the pool. This is cleanup only; the
				// request still gets at most one retry.
				p.finishFailedReservation(ctx, replacementReservation, err)
			}
		}
	}
	if err != nil {
		log.Errorln("privateproxy: dial %s: %v", dest, err)
		return nil, fmt.Errorf("dial %s: %w", dest, err)
	}
	return conn, nil
}

func (p *PrivateProxy) dialReserved(ctx context.Context, dest string, reservation *privateProxyTunnelReservation) (C.Conn, error) {
	if reservation == nil || reservation.tunnel() == nil {
		return nil, errors.New("privateproxy: tunnel reservation is nil")
	}
	conn, err := reservation.tunnel().DialContext(ctx, dest)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("privateproxy: tunnel returned nil connection")
	}
	if !reservation.activate() {
		_ = conn.Close()
		return nil, errors.New("privateproxy: tunnel reservation was released")
	}
	return &privateProxyConn{Conn: NewConn(conn, p), closeFunc: reservation.release}, nil
}

// finishFailedReservation retires an unusable session before releasing the
// caller's pending reservation. This ordering prevents another caller from
// selecting the failed session in the gap between those operations.
func (p *PrivateProxy) finishFailedReservation(ctx context.Context, reservation *privateProxyTunnelReservation, err error) bool {
	contextActive := ctx == nil || ctx.Err() == nil
	retry := reservation != nil && shouldRetryPrivateProxyDial(reservation.tunnel(), err) && contextActive
	if retry {
		p.retireTunnel(reservation.state)
	}
	if reservation != nil {
		reservation.release()
	}
	return retry
}

func shouldRetryPrivateProxyDial(t privateProxyTunnel, err error) bool {
	return errors.Is(err, tunnel.ErrControlPlaneFailure) || (t != nil && t.IsClosed())
}

func (p *PrivateProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !p.SupportUDP() {
		return nil, fmt.Errorf("privateproxy: UDP requires transport http3")
	}
	if metadata == nil {
		return nil, errors.New("privateproxy: metadata is nil")
	}
	if err := p.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	reservation, err := p.reserveTunnel(ctx)
	if err != nil {
		return nil, fmt.Errorf("privateproxy UDP tunnel: %w", err)
	}
	t := reservation.tunnel()
	if t == nil {
		reservation.release()
		return nil, errors.New("privateproxy UDP tunnel is nil")
	}
	packetConn, err := p.listenPacketReserved(ctx, reservation)
	if err != nil && p.finishFailedReservation(ctx, reservation, err) {
		if replacementReservation, replacementErr := p.reserveTunnel(ctx); replacementErr == nil {
			packetConn, err = p.listenPacketReserved(ctx, replacementReservation)
			if err != nil {
				p.finishFailedReservation(ctx, replacementReservation, err)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("privateproxy UDP association: %w", err)
	}
	return packetConn, nil
}

func (p *PrivateProxy) listenPacketReserved(ctx context.Context, reservation *privateProxyTunnelReservation) (C.PacketConn, error) {
	if reservation == nil || reservation.tunnel() == nil {
		return nil, errors.New("privateproxy UDP tunnel reservation is nil")
	}
	packetConn, err := reservation.tunnel().ListenPacketContext(ctx)
	if err != nil {
		return nil, err
	}
	if packetConn == nil {
		return nil, errors.New("privateproxy UDP tunnel returned nil packet connection")
	}
	if !reservation.activate() {
		_ = packetConn.Close()
		return nil, errors.New("privateproxy UDP tunnel reservation was released")
	}
	return &privateProxyPacketConn{PacketConn: NewPacketConn(packetConn, p), closeFunc: reservation.release}, nil
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
			return &privateProxyTunnelReservation{owner: p, state: best}, nil
		}
		if live >= p.option.SessionPool {
			// Defensive fallback for a zero/invalid threshold; normal validation
			// makes this branch equivalent to the soft-degrade condition above.
			if best != nil {
				best.pending.Add(1)
				p.mu.Unlock()
				return &privateProxyTunnelReservation{owner: p, state: best}, nil
			}
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		if best != nil && p.refillCoolingDown() {
			best.pending.Add(1)
			p.mu.Unlock()
			return &privateProxyTunnelReservation{owner: p, state: best}, nil
		}
		p.mu.Unlock()

		// Serialize pool growth. Requests can bypass an in-progress refill only
		// when a live session is below the admission threshold. If all sessions
		// are full, waiting for the one shared refill provides backpressure instead
		// of overloading the same TCP writer while a replacement is being created.
		if !p.dialMu.TryLock() {
			p.mu.Lock()
			p.pruneClosedLocked()
			best, live, bestLoad = p.bestSessionLocked()
			if best != nil && !p.closed &&
				(bestLoad < p.option.MaxStreamsPerSession || live >= p.option.SessionPool || p.refillCoolingDown()) {
				best.pending.Add(1)
				p.mu.Unlock()
				return &privateProxyTunnelReservation{owner: p, state: best}, nil
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
			return &privateProxyTunnelReservation{owner: p, state: best}, nil
		}
		if live >= p.option.SessionPool {
			if best != nil {
				best.pending.Add(1)
				p.mu.Unlock()
				p.dialMu.Unlock()
				return &privateProxyTunnelReservation{owner: p, state: best}, nil
			}
			p.mu.Unlock()
			p.dialMu.Unlock()
			return nil, net.ErrClosed
		}
		if best != nil && p.refillCoolingDown() {
			best.pending.Add(1)
			p.mu.Unlock()
			p.dialMu.Unlock()
			return &privateProxyTunnelReservation{owner: p, state: best}, nil
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
			p.resetRefillBackoff()
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
		backoff := p.noteRefillFailure()
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
			log.Warnln("privateproxy: session pool refill failed for %s; reusing a healthy session for %s: %v", p.addr, backoff, err)
			return &privateProxyTunnelReservation{owner: p, state: best}, nil
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
		if state == nil || state.retired || state.tunnel == nil || state.tunnel.IsClosed() {
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

func (p *PrivateProxy) refillCoolingDown() bool {
	return p.refillAt.Load() > time.Now().UnixNano()
}

func (p *PrivateProxy) noteRefillFailure() time.Duration {
	failures := p.refillFail.Add(1)
	shift := failures - 1
	if shift > 6 {
		shift = 6
	}
	delay := privateProxyRefillBaseDelay * time.Duration(uint64(1)<<shift)
	if delay > privateProxyRefillMaxDelay {
		delay = privateProxyRefillMaxDelay
	}
	p.refillAt.Store(time.Now().Add(delay).UnixNano())
	return delay
}

func (p *PrivateProxy) resetRefillBackoff() {
	p.refillFail.Store(0)
	p.refillAt.Store(0)
}

func (p *PrivateProxy) serverEntry() tunnel.ServerEntry {
	entry := tunnel.ServerEntry{
		Name: p.option.Name, Address: p.addr, SNI: p.option.SNI,
		NodeID: uint32(p.option.NodeID), Weight: 10,
		CAFile: p.option.CAFile, SPKIPins: p.option.SPKIPins, Transport: p.option.Transport,
	}
	if p.dialer != nil {
		entry.RawDialContext = p.dialer.DialContext
		entry.RawPacketDialContext = func(ctx context.Context, address string) (net.PacketConn, net.Addr, error) {
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				return nil, nil, err
			}
			port, err := strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 {
				return nil, nil, fmt.Errorf("invalid UDP port %q", portText)
			}
			ip, err := resolver.ResolveIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
			if err != nil {
				return nil, nil, err
			}
			remote := netip.AddrPortFrom(ip, uint16(port))
			packetConn, err := p.dialer.ListenPacket(ctx, "udp", "", remote)
			if err != nil {
				return nil, nil, err
			}
			return packetConn, net.UDPAddrFromAddrPort(remote), nil
		}
	}
	return entry
}

func (p *PrivateProxy) retireTunnel(target *privateProxyTunnelState) {
	if target == nil || target.tunnel == nil {
		return
	}
	var closeTarget *privateProxyTunnelState
	p.mu.Lock()
	live := p.tunnels[:0]
	for _, state := range p.tunnels {
		if state != target {
			live = append(live, state)
			continue
		}
		state.retired = true
		if state.tunnel.IsClosed() || (state.pending.Load() == 0 && state.active.Load() == 0) {
			closeTarget = state
		} else {
			live = append(live, state)
		}
	}
	p.tunnels = live
	p.mu.Unlock()
	if closeTarget != nil {
		_ = closeTarget.close()
	}
}

func (p *PrivateProxy) closeRetiredIfDrained(target *privateProxyTunnelState) {
	if target == nil || target.tunnel == nil {
		return
	}
	var closeTarget *privateProxyTunnelState
	p.mu.Lock()
	if target.retired && (target.tunnel.IsClosed() ||
		(target.pending.Load() == 0 && target.active.Load() == 0)) {
		live := p.tunnels[:0]
		for _, state := range p.tunnels {
			if state == target {
				closeTarget = state
				continue
			}
			live = append(live, state)
		}
		p.tunnels = live
	}
	p.mu.Unlock()
	if closeTarget != nil {
		_ = closeTarget.close()
	}
}

func (p *PrivateProxy) SupportUDP() bool {
	return p != nil && strings.EqualFold(strings.TrimSpace(p.option.Transport), "http3")
}

func (p *PrivateProxy) Alive() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, state := range p.tunnels {
		if state != nil && !state.retired && state.tunnel != nil && !state.tunnel.IsClosed() {
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
			if err := state.close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
