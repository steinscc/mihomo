package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/miekg/dns"

	"private_proxy/pkg/tunnel"
)

type fakePrivateProxyTunnel struct {
	closed  bool
	streams int
}

func (t *fakePrivateProxyTunnel) DialContext(context.Context, string) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (t *fakePrivateProxyTunnel) Close() error {
	t.closed = true
	return nil
}

func (t *fakePrivateProxyTunnel) IsClosed() bool { return t.closed }

func (t *fakePrivateProxyTunnel) NumStreams() int { return t.streams }

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
	mu      sync.Mutex
	closed  bool
	dialErr error
	streams int
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

func (t *scriptedPrivateProxyTunnel) Close() error {
	t.mu.Lock()
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
}

func TestPrivateProxySelectsLeastLoadedTunnelWithRoundRobinTies(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "load-balance-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	leastLoadedA := &fakePrivateProxyTunnel{streams: 1}
	leastLoadedB := &fakePrivateProxyTunnel{streams: 1}
	mostLoaded := &fakePrivateProxyTunnel{streams: 4}
	proxy.tunnels = []privateProxyTunnel{mostLoaded, leastLoadedA, leastLoadedB}

	for i, want := range []privateProxyTunnel{leastLoadedA, leastLoadedB, leastLoadedA, leastLoadedB} {
		got := proxy.selectTunnel(true)
		if got != want {
			t.Fatalf("selection %d: got %p, want %p", i, got, want)
		}
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

func TestPrivateProxyBuildsAndReusesPoolOnDemand(t *testing.T) {
	proxy, err := NewPrivateProxy(PrivateProxyOption{
		Name: "pool-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 2,
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
		Name: "partial-pool-test", Server: "proxy.example.com",
		PSK: "0123456789abcdef0123456789abcdef", SessionPool: 2,
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
