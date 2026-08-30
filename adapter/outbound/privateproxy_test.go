package outbound

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/miekg/dns"

	"private_proxy/pkg/tunnel"
)

type fakePrivateProxyTunnel struct {
	mu      sync.Mutex
	closed  bool
	streams int
}

func (t *fakePrivateProxyTunnel) DialContext(context.Context, string) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (t *fakePrivateProxyTunnel) ListenPacketContext(context.Context) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func (t *fakePrivateProxyTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

func (t *fakePrivateProxyTunnel) IsClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *fakePrivateProxyTunnel) NumStreams() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streams
}

func (t *fakePrivateProxyTunnel) setStreams(streams int) {
	t.mu.Lock()
	t.streams = streams
	t.mu.Unlock()
}

type recordingDialer struct {
	mu      sync.Mutex
	network string
	address string
}

func (d *recordingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.network = network
	d.address = address
	d.mu.Unlock()
	conn, peer := net.Pipe()
	_ = peer.Close()
	return conn, nil
}

func (d *recordingDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("packet dialing is not used by privateproxy")
}

type scriptedPrivateProxyTunnel struct {
	mu         sync.Mutex
	closed     bool
	closeCalls int
	dialErr    error
	streams    int
}

func (t *scriptedPrivateProxyTunnel) DialContext(context.Context, string) (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	if t.dialErr != nil {
		return nil, t.dialErr
	}
	conn, peer := net.Pipe()
	_ = peer.Close()
	return conn, nil
}

func (t *scriptedPrivateProxyTunnel) ListenPacketContext(context.Context) (net.PacketConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	if t.dialErr != nil {
		return nil, t.dialErr
	}
	return &privateProxyTestPacketConn{}, nil
}

func (t *scriptedPrivateProxyTunnel) Close() error {
	t.mu.Lock()
	t.closeCalls++
	t.closed = true
	t.mu.Unlock()
	return nil
}

func (t *scriptedPrivateProxyTunnel) IsClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *scriptedPrivateProxyTunnel) NumStreams() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streams
}

func (t *scriptedPrivateProxyTunnel) setDialErr(err error) {
	t.mu.Lock()
	t.dialErr = err
	t.mu.Unlock()
}

func (t *scriptedPrivateProxyTunnel) closeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeCalls
}

type dialResultPrivateProxyTunnel struct {
	mu      sync.Mutex
	closed  bool
	streams int
	err     error
}

func (t *dialResultPrivateProxyTunnel) DialContext(context.Context, string) (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	if t.err != nil {
		return nil, t.err
	}
	conn, peer := net.Pipe()
	_ = peer.Close()
	return conn, nil
}

func (t *dialResultPrivateProxyTunnel) ListenPacketContext(context.Context) (net.PacketConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	if t.err != nil {
		return nil, t.err
	}
	return &privateProxyTestPacketConn{}, nil
}

type privateProxyTestPacketConn struct{}

func (*privateProxyTestPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (*privateProxyTestPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}
func (*privateProxyTestPacketConn) Close() error                     { return nil }
func (*privateProxyTestPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*privateProxyTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (*privateProxyTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*privateProxyTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

func (t *dialResultPrivateProxyTunnel) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	return nil
}

func (t *dialResultPrivateProxyTunnel) IsClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *dialResultPrivateProxyTunnel) NumStreams() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streams
}

type privateProxyResolver struct {
	ip netip.Addr
}

func (r privateProxyResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}

func (r privateProxyResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}

func (r privateProxyResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, resolver.ErrIPv6Disabled
}

func (privateProxyResolver) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, nil
}

func (privateProxyResolver) ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error) {
	return nil, errors.New("DNS exchange is not used by privateproxy test resolver")
}

func (privateProxyResolver) Invalid() bool { return true }

func (privateProxyResolver) ClearCache()      {}
func (privateProxyResolver) ResetConnection() {}

func TestNewPrivateProxyIsLazy(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name:   "lazy-test",
		Server: "unresolvable.invalid",
		Port:   443,
		PSK:    "0123456789abcdef0123456789abcdef",
		SNI:    "unresolvable.invalid",
		NodeID: 1,
	})
	if err != nil {
		t.Fatalf("NewPrivateProxy must not dial during config load: %v", err)
	}
	if proxy.Alive() {
		t.Fatal("new on-demand proxy should not have a live tunnel")
	}
	if len(proxy.tunnels) != 0 {
		t.Fatal("constructor must not create pooled tunnels")
	}
	if proxy.option.SessionPool != defaultPrivateProxySessionPool {
		t.Fatalf("default session pool: got %d, want %d", proxy.option.SessionPool, defaultPrivateProxySessionPool)
	}
	if proxy.option.MaxStreamsPerSession != defaultMaxStreamsPerSession {
		t.Fatalf("default max streams per session: got %d, want %d", proxy.option.MaxStreamsPerSession, defaultMaxStreamsPerSession)
	}
}

func TestPrivateProxyMarshalJSONPoolMetrics(t *testing.T) {
	tests := []struct {
		name          string
		transport     string
		wantTransport string
		wantLive      int
		wantRetired   int
		wantActive    int64
		wantPending   int64
	}{
		{
			name:          "empty transport and live retired closed sessions",
			wantTransport: "tls-yamux",
			wantLive:      1,
			wantRetired:   1,
			wantActive:    7,
			wantPending:   10,
		},
		{
			name:          "http3 transport",
			transport:     " HTTP3 ",
			wantTransport: "http3",
			wantLive:      1,
			wantRetired:   1,
			wantActive:    7,
			wantPending:   10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := NewPrivateProxy(PrivateProxyOption{
				Name: "json-metrics-test", Server: "proxy.example.com",
				PSK: "0123456789abcdef0123456789abcdef", Transport: tt.transport,
				SessionPool: 3, MaxStreamsPerSession: 12,
			})
			if err != nil {
				t.Fatal(err)
			}

			live := &privateProxyTunnelState{tunnel: &fakePrivateProxyTunnel{}}
			live.active.Store(2)
			live.pending.Store(3)
			retired := &privateProxyTunnelState{tunnel: &fakePrivateProxyTunnel{}, retired: true}
			retired.active.Store(5)
			retired.pending.Store(7)
			closed := &privateProxyTunnelState{tunnel: &fakePrivateProxyTunnel{}}
			closed.active.Store(11)
			closed.pending.Store(13)
			if err := closed.tunnel.Close(); err != nil {
				t.Fatal(err)
			}
			closedRetired := &privateProxyTunnelState{tunnel: &fakePrivateProxyTunnel{}, retired: true}
			closedRetired.active.Store(17)
			closedRetired.pending.Store(19)
			if err := closedRetired.tunnel.Close(); err != nil {
				t.Fatal(err)
			}
			proxy.mu.Lock()
			proxy.tunnels = []*privateProxyTunnelState{live, retired, closed, closedRetired}
			proxy.mu.Unlock()

			payload, err := json.Marshal(proxy)
			if err != nil {
				t.Fatalf("marshal privateproxy: %v", err)
			}
			var document struct {
				Type string                  `json:"type"`
				ID   string                  `json:"id"`
				Pool privateProxyPoolMetrics `json:"privateproxy_pool"`
			}
			if err := json.Unmarshal(payload, &document); err != nil {
				t.Fatalf("unmarshal privateproxy: %v", err)
			}
			if document.Type != proxy.Type().String() || document.ID != proxy.Id() {
				t.Fatalf("base identity: type=%q id=%q, want type=%q id=%q", document.Type, document.ID, proxy.Type().String(), proxy.Id())
			}
			if document.Pool.Transport != tt.wantTransport {
				t.Errorf("transport: got %q, want %q", document.Pool.Transport, tt.wantTransport)
			}
			if document.Pool.SessionPoolLimit != 3 || document.Pool.MaxStreamsPerSession != 12 {
				t.Errorf("pool limits: got %d/%d, want 3/12", document.Pool.SessionPoolLimit, document.Pool.MaxStreamsPerSession)
			}
			if document.Pool.SessionsLive != tt.wantLive || document.Pool.SessionsRetired != tt.wantRetired {
				t.Errorf("sessions: got live=%d retired=%d, want live=%d retired=%d", document.Pool.SessionsLive, document.Pool.SessionsRetired, tt.wantLive, tt.wantRetired)
			}
			if document.Pool.StreamsActive != tt.wantActive || document.Pool.StreamsPending != tt.wantPending {
				t.Errorf("streams: got active=%d pending=%d, want active=%d pending=%d", document.Pool.StreamsActive, document.Pool.StreamsPending, tt.wantActive, tt.wantPending)
			}
			for _, secret := range []string{"0123456789abcdef0123456789abcdef", "proxy.example.com:443", "example.com"} {
				if strings.Contains(string(payload), secret) {
					t.Errorf("JSON unexpectedly contains sensitive value %q: %s", secret, payload)
				}
			}
		})
	}
}

func TestPrivateProxyMarshalJSONTracksReservationBalance(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "json-reservation-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	state := &privateProxyTunnelState{tunnel: &fakePrivateProxyTunnel{}}
	proxy.mu.Lock()
	proxy.tunnels = []*privateProxyTunnelState{state}
	proxy.mu.Unlock()

	reservation, err := proxy.reserveTunnel(context.Background())
	if err != nil {
		t.Fatalf("reserve tunnel: %v", err)
	}
	stages := []struct {
		name        string
		apply       func() bool
		wantActive  int64
		wantPending int64
	}{
		{name: "pending", wantPending: 1},
		{
			name: "active", apply: reservation.activate,
			wantActive: 1,
		},
		{
			name: "released", apply: func() bool {
				reservation.release()
				return true
			},
		},
		{
			name: "duplicate release", apply: func() bool {
				reservation.release()
				return true
			},
		},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			if stage.apply != nil && !stage.apply() {
				t.Fatal("reservation state transition failed")
			}
			metrics := marshalPrivateProxyPoolMetrics(t, proxy)
			if metrics.StreamsActive != stage.wantActive || metrics.StreamsPending != stage.wantPending {
				t.Fatalf("streams: got active=%d pending=%d, want active=%d pending=%d", metrics.StreamsActive, metrics.StreamsPending, stage.wantActive, stage.wantPending)
			}
		})
	}
}

func TestPrivateProxyMarshalJSONConcurrentReservations(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "json-race-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 1,
		MaxStreamsPerSession: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	state := &privateProxyTunnelState{tunnel: &fakePrivateProxyTunnel{}}
	proxy.mu.Lock()
	proxy.tunnels = []*privateProxyTunnelState{state}
	proxy.mu.Unlock()

	const workers = 8
	const iterations = 32
	start := make(chan struct{})
	errs := make(chan error, workers*iterations)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				reservation, err := proxy.reserveTunnel(context.Background())
				if err != nil {
					errs <- err
					continue
				}
				if !reservation.activate() {
					errs <- errors.New("reservation activation failed")
					reservation.release()
					continue
				}
				if _, err := json.Marshal(proxy); err != nil {
					errs <- err
				}
				reservation.release()
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := state.active.Load() + state.pending.Load(); got != 0 {
		t.Fatalf("reservation counters leaked: %d", got)
	}
}

func marshalPrivateProxyPoolMetrics(t *testing.T, proxy *PrivateProxy) privateProxyPoolMetrics {
	t.Helper()
	payload, err := json.Marshal(proxy)
	if err != nil {
		t.Fatalf("marshal privateproxy: %v", err)
	}
	var document struct {
		Pool privateProxyPoolMetrics `json:"privateproxy_pool"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("unmarshal privateproxy: %v", err)
	}
	return document.Pool
}

func TestPrivateProxyReservationsBalanceLeastLoadedTies(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "load-balance-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 3, MaxStreamsPerSession: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	leastLoadedA := &fakePrivateProxyTunnel{streams: 1}
	leastLoadedB := &fakePrivateProxyTunnel{streams: 1}
	mostLoaded := &fakePrivateProxyTunnel{streams: 4}
	proxy.tunnels = []*privateProxyTunnelState{
		{tunnel: mostLoaded}, {tunnel: leastLoadedA}, {tunnel: leastLoadedB},
	}

	first, err := proxy.reserveTunnel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := proxy.reserveTunnel(context.Background())
	if err != nil {
		first.release()
		t.Fatal(err)
	}
	defer first.release()
	defer second.release()
	if first.tunnel() != leastLoadedA || second.tunnel() != leastLoadedB {
		t.Fatalf("tie reservations: got %p/%p, want %p/%p", first.tunnel(), second.tunnel(), leastLoadedA, leastLoadedB)
	}
}

func TestPrivateProxyPropagatesBasicOptionsAndInjectsDialer(t *testing.T) {
	recording := &recordingDialer{}
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "basic-options", Server: "proxy.example.com", Port: 443,
		PSK: "0123456789abcdef0123456789abcdef", NodeID: 7,
		BasicOption: BasicOption{
			TFO:          true,
			MPTCP:        true,
			Interface:    "Ethernet 7",
			RoutingMark:  1234,
			IPVersion:    C.IPv4Only,
			ProviderName: "provider-a",
			DialerForAPI: recording,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	info := proxy.ProxyInfo()
	checks := []struct {
		name string
		got  any
		want any
	}{
		{name: "tfo", got: info.TFO, want: true},
		{name: "mptcp", got: info.MPTCP, want: true},
		{name: "interface", got: info.Interface, want: "Ethernet 7"},
		{name: "routing mark", got: info.RoutingMark, want: 1234},
		{name: "provider", got: info.ProviderName, want: "provider-a"},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s: got %v, want %v", check.name, check.got, check.want)
		}
	}

	entry := proxy.serverEntry()
	if entry.RawDialContext == nil {
		t.Fatal("privateproxy server entry must inject the Mihomo raw dialer")
	}
	conn, err := entry.RawDialContext(context.Background(), "tcp4", "proxy.example.com:443")
	if err != nil {
		t.Fatalf("injected raw dialer: %v", err)
	}
	_ = conn.Close()
	recording.mu.Lock()
	gotNetwork, gotAddress := recording.network, recording.address
	recording.mu.Unlock()
	if gotNetwork != "tcp4" || gotAddress != "proxy.example.com:443" {
		t.Fatalf("raw dial arguments: got %s %s", gotNetwork, gotAddress)
	}
	if entry.RawPacketDialContext == nil {
		t.Fatal("privateproxy server entry must inject the Mihomo packet dialer")
	}
}

func TestPrivateProxyUsesProxyServerResolverForRawDial(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	oldResolver := resolver.ProxyServerHostResolver
	resolver.ProxyServerHostResolver = privateProxyResolver{ip: netip.MustParseAddr("127.0.0.1")}
	defer func() { resolver.ProxyServerHostResolver = oldResolver }()

	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "resolver-injection", Server: "proxy.example.com", Port: 443,
		PSK: "0123456789abcdef0123456789abcdef", NodeID: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	entry := proxy.serverEntry()
	if entry.RawDialContext == nil {
		t.Fatal("privateproxy server entry must inject a raw dialer")
	}
	acceptErr := make(chan error, 1)
	go func() {
		acceptedConn, err := listener.Accept()
		if acceptedConn != nil {
			_ = acceptedConn.Close()
		}
		acceptErr <- err
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := entry.RawDialContext(context.Background(), "tcp", "proxy.example.com:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("raw dial through proxy resolver: %v", err)
	}
	_ = conn.Close()
	if err := <-acceptErr; err != nil {
		t.Fatalf("accept raw dial: %v", err)
	}

	udpListener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	if entry.RawPacketDialContext == nil {
		t.Fatal("privateproxy server entry must inject a raw packet dialer")
	}
	udpPort := udpListener.LocalAddr().(*net.UDPAddr).Port
	packetConn, remoteAddr, err := entry.RawPacketDialContext(
		context.Background(), "proxy.example.com:"+strconv.Itoa(udpPort),
	)
	if err != nil {
		t.Fatalf("raw packet dial through proxy resolver: %v", err)
	}
	defer packetConn.Close()
	remoteUDP, ok := remoteAddr.(*net.UDPAddr)
	if !ok || !remoteUDP.IP.Equal(net.ParseIP("127.0.0.1")) || remoteUDP.Port != udpPort {
		t.Fatalf("resolved UDP address: got %v", remoteAddr)
	}
}

func TestNewPrivateProxyRejectsWeakPSK(t *testing.T) {
	_, err := NewPrivateProxy(PrivateProxyOption{
		Name:   "weak-psk",
		Server: "proxy.example.com",
		PSK:    "short",
	})
	if err == nil {
		t.Fatal("expected weak PSK validation error")
	}
}

func TestPrivateProxyUDPRequiresHTTP3(t *testing.T) {
	base := PrivateProxyOption{
		Name: "udp", Server: "proxy.example.com", Port: 443,
		PSK: "0123456789abcdef0123456789abcdef", NodeID: 1,
		SessionPool: 1,
	}
	v1, err := NewPrivateProxy(base)
	if err != nil {
		t.Fatal(err)
	}
	if v1.SupportUDP() {
		t.Fatal("V1 unexpectedly advertises UDP")
	}
	if _, err := v1.ListenPacketContext(context.Background(), &C.Metadata{}); err == nil {
		t.Fatal("V1 UDP association unexpectedly succeeded")
	}

	base.Transport = "http3"
	v2, err := NewPrivateProxy(base)
	if err != nil {
		t.Fatal(err)
	}
	if !v2.SupportUDP() {
		t.Fatal("HTTP/3 transport does not advertise UDP")
	}
	v2.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
		return &scriptedPrivateProxyTunnel{}, nil
	}
	metadata := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 53}
	packetConn, err := v2.ListenPacketContext(context.Background(), metadata)
	if err != nil {
		t.Fatalf("HTTP/3 UDP association: %v", err)
	}
	if packetConn == nil {
		t.Fatal("HTTP/3 UDP association returned nil")
	}
	_ = packetConn.Close()
}

func TestPrivateProxyUDPRetriesControlPlaneFailure(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "udp-retry", Server: "proxy.example.com", Port: 443,
		PSK: "0123456789abcdef0123456789abcdef", NodeID: 1,
		Transport: "http3", SessionPool: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	first := &scriptedPrivateProxyTunnel{dialErr: errors.Join(errors.New("UDP control read"), tunnel.ErrControlPlaneFailure)}
	replacement := &scriptedPrivateProxyTunnel{}
	dials := 0
	proxy.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
		dials++
		if dials == 1 {
			return first, nil
		}
		if dials == 2 {
			return replacement, nil
		}
		return nil, errors.New("unexpected extra UDP retry")
	}
	metadata := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 53}
	packetConn, err := proxy.ListenPacketContext(context.Background(), metadata)
	if err != nil {
		t.Fatalf("UDP control-plane retry: %v", err)
	}
	if packetConn == nil || dials != 2 || !first.IsClosed() || replacement.IsClosed() {
		t.Fatalf("retry state: conn=%v dials=%d firstClosed=%v replacementClosed=%v", packetConn, dials, first.IsClosed(), replacement.IsClosed())
	}
	_ = packetConn.Close()
}

func TestNewPrivateProxyValidatesSessionPool(t *testing.T) {
	for _, size := range []int{-1, maxPrivateProxySessionPool + 1} {
		_, err := NewPrivateProxy(PrivateProxyOption{
			Name: "pool-test", Server: "proxy.example.com",
			PSK: "0123456789abcdef0123456789abcdef", SessionPool: size,
		})
		if err == nil {
			t.Fatalf("session_pool=%d should be rejected", size)
		}
	}

	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "pool-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: maxPrivateProxySessionPool,
	})
	if err != nil {
		t.Fatalf("maximum session pool should be accepted: %v", err)
	}
	if proxy.option.SessionPool != maxPrivateProxySessionPool {
		t.Fatalf("session pool: got %d, want %d", proxy.option.SessionPool, maxPrivateProxySessionPool)
	}
}

func TestNewPrivateProxyValidatesMaxStreamsPerSession(t *testing.T) {
	for _, size := range []int{-1, maxMaxStreamsPerSession + 1} {
		_, err := NewPrivateProxy(PrivateProxyOption{
			Name: "stream-threshold-test", Server: "proxy.example.com",
			PSK: "0123456789abcdef0123456789abcdef", MaxStreamsPerSession: size,
		})
		if err == nil {
			t.Fatalf("max_streams_per_session=%d should be rejected", size)
		}
	}

	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "stream-threshold-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", MaxStreamsPerSession: maxMaxStreamsPerSession,
	})
	if err != nil {
		t.Fatalf("maximum max_streams_per_session should be accepted: %v", err)
	}
	if proxy.option.MaxStreamsPerSession != maxMaxStreamsPerSession {
		t.Fatalf("max streams per session: got %d, want %d", proxy.option.MaxStreamsPerSession, maxMaxStreamsPerSession)
	}
}

func TestPrivateProxyBuildsAndReusesPoolOnDemand(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "pool-test", Server: "proxy.example.com", SessionPool: 2, MaxStreamsPerSession: 1,
		PSK: "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}

	dials := 0
	proxy.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
		dials++
		return &fakePrivateProxyTunnel{}, nil
	}

	first, err := proxy.getOrCreateTunnel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	proxy.tunnels[0].tunnel.(*fakePrivateProxyTunnel).setStreams(1)
	second, err := proxy.getOrCreateTunnel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	third, err := proxy.getOrCreateTunnel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dials != 2 {
		t.Fatalf("dial count: got %d, want 2", dials)
	}
	if first == second {
		t.Fatal("the first two requests should establish independent sessions")
	}
	if third != first && third != second {
		t.Fatal("requests after the pool is full must reuse an existing session")
	}

	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if !first.IsClosed() || !second.IsClosed() {
		t.Fatal("closing the adapter must close every pooled session")
	}
}

func TestPrivateProxyUsesHealthyPartialPoolWhenRefillFails(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "partial-pool-test", Server: "proxy.example.com", SessionPool: 2, MaxStreamsPerSession: 1,
		PSK: "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	dials := 0
	proxy.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
		dials++
		if dials == 2 {
			return nil, errors.New("refill unavailable")
		}
		return &fakePrivateProxyTunnel{}, nil
	}

	healthy, err := proxy.getOrCreateTunnel(context.Background())
	if err != nil {
		t.Fatalf("create first session: %v", err)
	}
	proxy.tunnels[0].tunnel.(*fakePrivateProxyTunnel).setStreams(1)
	fallback, err := proxy.getOrCreateTunnel(context.Background())
	if err != nil {
		t.Fatalf("partial pool should remain usable after refill failure: %v", err)
	}
	if fallback != healthy {
		t.Fatal("refill failure should fall back to the existing healthy session")
	}
	if dials != 2 {
		t.Fatalf("dial count: got %d, want 2", dials)
	}
	cooldownFallback, err := proxy.getOrCreateTunnel(context.Background())
	if err != nil {
		t.Fatalf("cooldown fallback: %v", err)
	}
	if cooldownFallback != healthy || dials != 2 {
		t.Fatalf("cooldown retried refill: fallback=%p healthy=%p dials=%d", cooldownFallback, healthy, dials)
	}
	proxy.refillAt.Store(time.Now().Add(-time.Second).UnixNano())
	if _, err := proxy.getOrCreateTunnel(context.Background()); err != nil {
		t.Fatalf("expired cooldown fallback: %v", err)
	}
	if dials != 3 {
		t.Fatalf("expired cooldown did not retry refill: dials=%d, want 3", dials)
	}
}

func TestPrivateProxyReusesUnderThresholdWithoutRefillDial(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "partial-pool-capacity-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 2, MaxStreamsPerSession: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	first := &fakePrivateProxyTunnel{}
	dials := 0
	proxy.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
		dials++
		if dials > 1 {
			return nil, errors.New("refill must not be attempted while capacity is available")
		}
		return first, nil
	}

	got, err := proxy.getOrCreateTunnel(context.Background())
	if err != nil {
		t.Fatalf("create first session: %v", err)
	}
	if got != first {
		t.Fatalf("first session: got %p, want %p", got, first)
	}
	first.setStreams(1)
	got, err = proxy.getOrCreateTunnel(context.Background())
	if err != nil {
		t.Fatalf("reuse under threshold: %v", err)
	}
	if got != first {
		t.Fatalf("under-threshold session: got %p, want %p", got, first)
	}
	if dials != 1 {
		t.Fatalf("dial count: got %d, want 1", dials)
	}
}

func TestPrivateProxyExpandsOnlyAfterAllSessionsReachThreshold(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "threshold-expansion-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 3, MaxStreamsPerSession: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	dials := 0
	proxy.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
		dials++
		return &dialResultPrivateProxyTunnel{}, nil
	}

	first, err := proxy.reserveTunnel(context.Background())
	if err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	second, err := proxy.reserveTunnel(context.Background())
	if err != nil {
		t.Fatalf("second reservation: %v", err)
	}
	if first.state != second.state {
		t.Fatal("reservations below the threshold should share the first session")
	}
	third, err := proxy.reserveTunnel(context.Background())
	if err != nil {
		t.Fatalf("threshold expansion reservation: %v", err)
	}
	if third.state == first.state {
		t.Fatal("all capacity on the first session should trigger one new session")
	}
	if dials != 2 || len(proxy.tunnels) != 2 {
		t.Fatalf("pool expansion: dials=%d tunnels=%d, want 2/2", dials, len(proxy.tunnels))
	}
	first.release()
	second.release()
	third.release()
}

func TestPrivateProxyBackpressuresWhenOnlyLiveSessionIsAtThreshold(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "refill-contention-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 2, MaxStreamsPerSession: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	first := &dialResultPrivateProxyTunnel{streams: 2}
	proxy.tunnels = []*privateProxyTunnelState{{tunnel: first}}
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	proxy.dialTunnel = func(ctx context.Context, _ tunnel.ServerEntry, _ string) (privateProxyTunnel, error) {
		close(dialStarted)
		select {
		case <-releaseDial:
			return &dialResultPrivateProxyTunnel{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	refill := make(chan *privateProxyTunnelReservation, 1)
	refillErr := make(chan error, 1)
	go func() {
		lease, err := proxy.reserveTunnel(context.Background())
		refill <- lease
		refillErr <- err
	}()
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("refill dial did not start")
	}

	fast := make(chan *privateProxyTunnelReservation, 1)
	fastErr := make(chan error, 1)
	go func() {
		lease, err := proxy.reserveTunnel(context.Background())
		fast <- lease
		fastErr <- err
	}()
	select {
	case err := <-fastErr:
		lease := <-fast
		if lease != nil {
			lease.release()
		}
		t.Fatalf("threshold-full request bypassed the shared refill: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Expected: the existing session is at its threshold, so the second
		// request waits for the one in-progress expansion instead of adding more
		// load to the stalled TCP writer.
	}

	close(releaseDial)
	select {
	case err := <-refillErr:
		if err != nil {
			t.Fatalf("refill reservation: %v", err)
		}
		(<-refill).release()
	case <-time.After(time.Second):
		t.Fatal("refill reservation did not finish")
	}
	select {
	case err := <-fastErr:
		if err != nil {
			t.Fatalf("reservation after shared refill: %v", err)
		}
		lease := <-fast
		lease.release()
	case <-time.After(time.Second):
		t.Fatal("waiting reservation did not resume after refill")
	}
}

func TestPrivateProxyPendingReservationsBalanceConcurrentBurst(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "pending-fairness-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 2, MaxStreamsPerSession: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	left := &dialResultPrivateProxyTunnel{}
	right := &dialResultPrivateProxyTunnel{}
	proxy.tunnels = []*privateProxyTunnelState{{tunnel: left}, {tunnel: right}}

	const reservations = 64
	start := make(chan struct{})
	leases := make(chan *privateProxyTunnelReservation, reservations)
	errs := make(chan error, reservations)
	var wg sync.WaitGroup
	for i := 0; i < reservations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			lease, err := proxy.reserveTunnel(context.Background())
			if err != nil {
				errs <- err
				return
			}
			leases <- lease
		}()
	}
	close(start)
	wg.Wait()
	close(leases)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent reservation: %v", err)
	}

	counts := map[privateProxyTunnel]int{}
	collected := make([]*privateProxyTunnelReservation, 0, reservations)
	for lease := range leases {
		counts[lease.tunnel()]++
		collected = append(collected, lease)
	}
	if counts[left] < reservations/2-1 || counts[right] < reservations/2-1 {
		t.Fatalf("pending reservations were not balanced: left=%d right=%d", counts[left], counts[right])
	}
	for _, lease := range collected {
		lease.release()
	}
	if got := proxy.tunnels[0].pending.Load() + proxy.tunnels[1].pending.Load(); got != 0 {
		t.Fatalf("pending reservations leaked: %d", got)
	}
}

func TestPrivateProxyPoolCapSoftDegradesWhenThresholdIsFull(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "pool-cap-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 2, MaxStreamsPerSession: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	left := &dialResultPrivateProxyTunnel{streams: 1}
	right := &dialResultPrivateProxyTunnel{streams: 2}
	proxy.tunnels = []*privateProxyTunnelState{{tunnel: left}, {tunnel: right}}
	proxy.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
		return nil, errors.New("pool is already at its maximum")
	}

	lease, err := proxy.reserveTunnel(context.Background())
	if err != nil {
		t.Fatalf("full pool should soft-degrade: %v", err)
	}
	if lease.tunnel() != left {
		t.Fatalf("full pool selected %p, want least-loaded %p", lease.tunnel(), left)
	}
	lease.release()
}

func TestPrivateProxyDialReleasesPendingReservationOnSuccessAndFailure(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com", DstPort: 443}
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "failure", err: errors.New("upstream unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy, err := NewPrivateProxy(PrivateProxyOption{
				Name: "reservation-release-test", Server: "proxy.example.com", SessionPool: 1,
				PSK: "0123456789abcdef0123456789abcdef",
			})
			if err != nil {
				t.Fatal(err)
			}
			fake := &dialResultPrivateProxyTunnel{err: test.err}
			proxy.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
				return fake, nil
			}
			conn, dialErr := proxy.DialContext(context.Background(), metadata)
			if test.err == nil {
				if dialErr != nil || conn == nil {
					t.Fatalf("success: conn=%v err=%v", conn, dialErr)
				}
				_ = conn.Close()
			} else if dialErr == nil {
				t.Fatal("expected dial failure")
			}
			if got := proxy.tunnels[0].pending.Load(); got != 0 {
				t.Fatalf("pending reservation after %s: got %d, want 0", test.name, got)
			}
			_ = proxy.Close()
		})
	}
}

func TestPrivateProxyEvictsControlPlaneFailuresButNotConnectErrors(t *testing.T) {
	tests := []struct {
		name                 string
		firstErr             error
		wantRetry            bool
		wantFirstClosed      bool
		wantReplacementAlive bool
	}{
		{
			name:                 "control plane failure retries once",
			firstErr:             errors.Join(errors.New("read header"), tunnel.ErrControlPlaneFailure),
			wantRetry:            true,
			wantFirstClosed:      true,
			wantReplacementAlive: true,
		},
		{
			name:            "upstream connect error does not retry",
			firstErr:        errors.New("CONNECT rejected: connection refused"),
			wantRetry:       false,
			wantFirstClosed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := NewPrivateProxy(PrivateProxyOption{
				Name: "retry-test", Server: "proxy.example.com",
				PSK: "0123456789abcdef0123456789abcdef", SessionPool: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()

			first := &scriptedPrivateProxyTunnel{dialErr: tt.firstErr}
			replacement := &scriptedPrivateProxyTunnel{}
			dials := 0
			proxy.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
				dials++
				switch dials {
				case 1:
					return first, nil
				case 2:
					return replacement, nil
				default:
					return nil, errors.New("unexpected second retry")
				}
			}

			metadata := &C.Metadata{Host: "example.com", DstPort: 443}
			conn, dialErr := proxy.DialContext(context.Background(), metadata)
			if tt.wantRetry {
				if dialErr != nil {
					t.Fatalf("control-plane failure should retry: %v", dialErr)
				}
				if conn == nil {
					t.Fatal("retry should return a connection")
				}
				_ = conn.Close()
			} else if dialErr == nil {
				t.Fatal("ordinary CONNECT_ERROR must be returned without retry")
			}
			if (dials == 2) != tt.wantRetry {
				t.Fatalf("dial count: got %d, want retry=%v", dials, tt.wantRetry)
			}
			if first.IsClosed() != tt.wantFirstClosed {
				t.Fatalf("first tunnel closed: got %v, want %v", first.IsClosed(), tt.wantFirstClosed)
			}
			if tt.wantReplacementAlive && replacement.IsClosed() {
				t.Fatal("healthy replacement must remain in the pool")
			}
		})
	}
}

func TestPrivateProxyControlFailureDrainsActiveSibling(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "drain-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	first := &scriptedPrivateProxyTunnel{}
	replacement := &scriptedPrivateProxyTunnel{}
	dials := 0
	proxy.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
		dials++
		switch dials {
		case 1:
			return first, nil
		case 2:
			return replacement, nil
		default:
			return nil, errors.New("unexpected extra drain-test dial")
		}
	}

	sibling, err := proxy.reserveTunnel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sibling.tunnel() != first || !sibling.activate() {
		t.Fatal("failed to establish active sibling reservation")
	}
	first.setDialErr(errors.Join(errors.New("read header"), tunnel.ErrControlPlaneFailure))

	metadata := &C.Metadata{Host: "example.com", DstPort: 443}
	conn, err := proxy.DialContext(context.Background(), metadata)
	if err != nil {
		t.Fatalf("replacement dial: %v", err)
	}
	if conn == nil || dials != 2 {
		t.Fatalf("replacement state: conn=%v dials=%d", conn, dials)
	}
	_ = conn.Close()
	if first.IsClosed() || first.closeCount() != 0 {
		t.Fatal("retired tunnel closed while an active sibling remained")
	}

	lease, err := proxy.reserveTunnel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lease.tunnel() != replacement {
		t.Fatal("retired tunnel was selected for new traffic")
	}
	lease.release()

	sibling.release()
	if !first.IsClosed() || first.closeCount() != 1 {
		t.Fatalf("drained tunnel close state: closed=%v calls=%d", first.IsClosed(), first.closeCount())
	}
	proxy.mu.RLock()
	for _, state := range proxy.tunnels {
		if state == sibling.state {
			proxy.mu.RUnlock()
			t.Fatal("drained tunnel remained in the pool")
		}
	}
	proxy.mu.RUnlock()
}

func TestPrivateProxyRetiredTunnelWaitsForPendingReservation(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "pending-drain-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	target := &scriptedPrivateProxyTunnel{}
	state := &privateProxyTunnelState{tunnel: target}
	state.pending.Store(1)
	proxy.tunnels = []*privateProxyTunnelState{state}
	reservation := &privateProxyTunnelReservation{owner: proxy, state: state}

	proxy.retireTunnel(state)
	if target.IsClosed() {
		t.Fatal("retired tunnel closed before its pending reservation finished")
	}
	reservation.release()
	if !target.IsClosed() || target.closeCount() != 1 {
		t.Fatalf("pending drain close state: closed=%v calls=%d", target.IsClosed(), target.closeCount())
	}
}

func TestPrivateProxyUDPTunnelDrainsAfterPacketConnClose(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "udp-drain-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", Transport: "http3", SessionPool: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	target := &scriptedPrivateProxyTunnel{}
	proxy.dialTunnel = func(context.Context, tunnel.ServerEntry, string) (privateProxyTunnel, error) {
		return target, nil
	}
	metadata := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 53}
	packetConn, err := proxy.ListenPacketContext(context.Background(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	proxy.mu.RLock()
	state := proxy.tunnels[0]
	proxy.mu.RUnlock()
	if state.active.Load() != 1 {
		t.Fatalf("active UDP association count: got %d, want 1", state.active.Load())
	}

	proxy.retireTunnel(state)
	if target.IsClosed() {
		t.Fatal("retired UDP tunnel closed while its packet connection remained active")
	}
	_ = packetConn.Close()
	if !target.IsClosed() || target.closeCount() != 1 {
		t.Fatalf("UDP drain close state: closed=%v calls=%d", target.IsClosed(), target.closeCount())
	}
}

const (
	privateProxyABTargetHost       = "example.com"
	privateProxyABTargetPort       = 443
	privateProxyABConcurrency      = 16
	privateProxyABOperationTimeout = 5 * time.Second
	privateProxyABGroupTimeout     = 60 * time.Second
)

// TestPrivateProxyV1SessionPoolABLive is an opt-in, sequential comparison of
// the two V1 admission thresholds. It deliberately uses one fixed public TLS
// target and no application download: the TLS handshakes plus the bounded
// CONNECT control frames are enough to exercise concurrent yamux streams while
// keeping the traffic well below the live-test budget.
func TestPrivateProxyV1SessionPoolABLive(t *testing.T) {
	if os.Getenv("PRIVATE_PROXY_AB_LIVE") != "1" {
		t.Skip("set PRIVATE_PROXY_AB_LIVE=1 to run the live V1 A/B test")
	}

	cfg, ok := loadPrivateProxyABLiveConfig(t)
	if !ok {
		return
	}

	// Keep the groups strictly sequential so the measurements cannot compete
	// for the same endpoint or contaminate one another's pool state.
	a := runPrivateProxyV1ABGroup(t, cfg, "A", 8)
	b := runPrivateProxyV1ABGroup(t, cfg, "B", 4)

	t.Logf(
		"privateproxy V1 A/B comparison target=%s p95_delta_B_minus_A=%v max_delta_B_minus_A=%v",
		privateProxyABTargetHost,
		b.p95-a.p95,
		b.max-a.max,
	)
	if a.connectSuccess == 0 || b.connectSuccess == 0 {
		t.Errorf("live V1 A/B produced no successful CONNECT in one or both groups")
	}
}

type privateProxyABLiveConfig struct {
	server string
	port   int
	sni    string
	psk    string
	nodeID int
}

// privateProxyABEnv prefers namespaced variables to avoid accidentally using
// an unrelated process setting, while accepting the short names requested by
// the operator-facing live-test contract.
func privateProxyABEnv(name string) string {
	if value := os.Getenv("PRIVATE_PROXY_AB_" + name); strings.TrimSpace(value) != "" {
		return value
	}
	return os.Getenv(name)
}

func loadPrivateProxyABLiveConfig(t *testing.T) (privateProxyABLiveConfig, bool) {
	t.Helper()
	address := strings.TrimSpace(privateProxyABEnv("ADDRESS"))
	sni := strings.TrimSpace(privateProxyABEnv("SNI"))
	psk := privateProxyABEnv("PSK")
	nodeIDText := strings.TrimSpace(privateProxyABEnv("NODE_ID"))
	if address == "" || sni == "" || strings.TrimSpace(psk) == "" || nodeIDText == "" {
		t.Skip("live V1 A/B requires ADDRESS, SNI, PSK, and NODE_ID")
		return privateProxyABLiveConfig{}, false
	}

	server, port, ok := splitPrivateProxyABAddress(address)
	if !ok {
		t.Skip("live V1 A/B ADDRESS is invalid")
		return privateProxyABLiveConfig{}, false
	}
	nodeID, err := strconv.ParseUint(nodeIDText, 10, 32)
	if err != nil || nodeID == 0 {
		t.Skip("live V1 A/B NODE_ID is invalid")
		return privateProxyABLiveConfig{}, false
	}
	return privateProxyABLiveConfig{
		server: server,
		port:   port,
		sni:    sni,
		psk:    psk,
		nodeID: int(nodeID),
	}, true
}

func splitPrivateProxyABAddress(address string) (string, int, bool) {
	if address == "" || strings.ContainsAny(address, "\r\n\t /") {
		return "", 0, false
	}
	if host, portText, err := net.SplitHostPort(address); err == nil {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 || host == "" {
			return "", 0, false
		}
		return host, port, true
	}
	if strings.Count(address, ":") > 1 {
		if net.ParseIP(address) == nil {
			return "", 0, false
		}
		return address, 443, true
	}
	return address, 443, true
}

type privateProxyV1ABSample struct {
	elapsed  time.Duration
	success  bool
	tlsProbe bool
}

type privateProxyV1ABGroupResult struct {
	label          string
	connectSuccess int
	connectFailure int
	tlsSuccess     int
	tlsFailure     int
	p50            time.Duration
	p95            time.Duration
	max            time.Duration
	pool           privateProxyPoolMetrics
}

func runPrivateProxyV1ABGroup(t *testing.T, cfg privateProxyABLiveConfig, label string, maxStreams int) privateProxyV1ABGroupResult {
	t.Helper()
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name:                 "privateproxy-v1-ab-" + label,
		Server:               cfg.server,
		Port:                 cfg.port,
		PSK:                  cfg.psk,
		SNI:                  cfg.sni,
		NodeID:               cfg.nodeID,
		SessionPool:          8,
		MaxStreamsPerSession: maxStreams,
	})
	if err != nil {
		t.Fatalf("live V1 A/B group %s could not initialize", label)
	}
	defer proxy.Close()

	groupCtx, cancelGroup := context.WithTimeout(context.Background(), privateProxyABGroupTimeout)
	defer cancelGroup()
	start := make(chan struct{})
	release := make(chan struct{})
	attemptsDone := make(chan struct{}, privateProxyABConcurrency)
	samples := make(chan privateProxyV1ABSample, privateProxyABConcurrency)
	metadata := &C.Metadata{Host: privateProxyABTargetHost, DstPort: privateProxyABTargetPort}
	var workers sync.WaitGroup
	workers.Add(privateProxyABConcurrency)
	for i := 0; i < privateProxyABConcurrency; i++ {
		go func() {
			defer workers.Done()
			<-start

			dialCtx, cancelDial := context.WithTimeout(groupCtx, privateProxyABOperationTimeout)
			started := time.Now()
			conn, dialErr := proxy.DialContext(dialCtx, metadata)
			elapsed := time.Since(started)
			cancelDial()
			if dialErr != nil || conn == nil {
				samples <- privateProxyV1ABSample{elapsed: elapsed}
				attemptsDone <- struct{}{}
				return
			}

			rawConn, ok := conn.(net.Conn)
			if !ok {
				_ = conn.Close()
				samples <- privateProxyV1ABSample{elapsed: elapsed, success: true}
				attemptsDone <- struct{}{}
				return
			}
			_ = rawConn.SetDeadline(time.Now().Add(privateProxyABOperationTimeout))
			probeCtx, cancelProbe := context.WithTimeout(groupCtx, privateProxyABOperationTimeout)
			tlsConn := tls.Client(rawConn, &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: privateProxyABTargetHost,
			})
			probeErr := tlsConn.HandshakeContext(probeCtx)
			cancelProbe()
			samples <- privateProxyV1ABSample{
				elapsed:  elapsed,
				success:  true,
				tlsProbe: probeErr == nil,
			}
			attemptsDone <- struct{}{}
			if probeErr != nil {
				_ = tlsConn.Close()
				return
			}

			select {
			case <-release:
			case <-groupCtx.Done():
			}
			_ = tlsConn.Close()
		}()
	}
	close(start)

	for i := 0; i < privateProxyABConcurrency; i++ {
		select {
		case <-attemptsDone:
		case <-groupCtx.Done():
			t.Errorf("live V1 A/B group %s exceeded its bounded runtime", label)
			i = privateProxyABConcurrency
		}
	}
	close(release)
	workers.Wait()
	close(samples)

	result := privateProxyV1ABGroupResult{label: label, pool: marshalPrivateProxyPoolMetrics(t, proxy)}
	var latencies []time.Duration
	for sample := range samples {
		if !sample.success {
			result.connectFailure++
			continue
		}
		result.connectSuccess++
		latencies = append(latencies, sample.elapsed)
		if sample.tlsProbe {
			result.tlsSuccess++
		} else {
			result.tlsFailure++
		}
	}
	if len(latencies) > 0 {
		result.p50 = privateProxyABPercentile(latencies, 50)
		result.p95 = privateProxyABPercentile(latencies, 95)
		result.max = latencies[0]
		for _, latency := range latencies[1:] {
			if latency > result.max {
				result.max = latency
			}
		}
	}
	t.Logf(
		"privateproxy V1 group=%s target=%s connect_success=%d connect_failure=%d tls_success=%d tls_failure=%d latency_samples=%d p50=%v p95=%v max=%v pool_transport=%s pool_session_limit=%d pool_max_streams=%d sessions_live=%d sessions_retired=%d streams_active=%d streams_pending=%d",
		label, privateProxyABTargetHost, result.connectSuccess, result.connectFailure,
		result.tlsSuccess, result.tlsFailure, len(latencies), result.p50, result.p95, result.max,
		result.pool.Transport, result.pool.SessionPoolLimit, result.pool.MaxStreamsPerSession,
		result.pool.SessionsLive, result.pool.SessionsRetired, result.pool.StreamsActive,
		result.pool.StreamsPending,
	)
	return result
}

func privateProxyABPercentile(values []time.Duration, percentile int) time.Duration {
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := (len(ordered)*percentile+99)/100 - 1
	if index < 0 {
		index = 0
	}
	if index >= len(ordered) {
		index = len(ordered) - 1
	}
	return ordered[index]
}
