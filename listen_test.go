package main

import "testing"

// TestResolveListenGate covers the "exposure requires login" rule.
func TestResolveListenGate(t *testing.T) {
	oldAddr, oldHash := listenAddr.Load(), authHash
	t.Cleanup(func() {
		listenAddr.Store(oldAddr)
		authHash = oldHash
		listenExposed, listenTLS = false, false
	})

	// non-loopback + login OFF → forced back to loopback, plain HTTP
	listenAddr.Store("0.0.0.0:5000")
	authHash = ""
	addr, _ := resolveListen()
	if listenExposed || listenTLS {
		t.Errorf("login off must not expose (exposed=%v tls=%v)", listenExposed, listenTLS)
	}
	if addr != "127.0.0.1:5000" {
		t.Errorf("expected loopback fallback, got %q", addr)
	}

	// non-loopback + login ON → exposed over HTTPS
	listenAddr.Store("0.0.0.0:5000")
	authHash = "hash"
	if _, _ = resolveListen(); !listenExposed || !listenTLS {
		t.Errorf("login on + non-loopback must expose over TLS (exposed=%v tls=%v)", listenExposed, listenTLS)
	}

	// loopback stays plain HTTP regardless of login
	listenAddr.Store("127.0.0.1:5000")
	authHash = "hash"
	if _, _ = resolveListen(); listenExposed || listenTLS {
		t.Errorf("loopback must stay HTTP (exposed=%v tls=%v)", listenExposed, listenTLS)
	}

	// default (empty) → loopback
	listenAddr.Store("")
	if addr, _ := resolveListen(); addr != "127.0.0.1:5000" {
		t.Errorf("empty addr should default to loopback, got %q", addr)
	}
}
