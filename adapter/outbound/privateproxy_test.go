package outbound

import (
	"context"
	"errors"
	"net"
	"testing"

	"private_proxy/pkg/tunnel"
)

type fakePrivateProxyTunnel struct {
	closed bool
}

func (t *fakePrivateProxyTunnel) DialContext(context.Context, string) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (t *fakePrivateProxyTunnel) Close() error {
	t.closed = true
	return nil
}

func (t *fakePrivateProxyTunnel) IsClosed() bool { return t.closed }

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
