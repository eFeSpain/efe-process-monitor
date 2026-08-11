package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Bind/TLS model: the dashboard binds 127.0.0.1 by default (HTTP, fine — never
// leaves the machine). If the operator sets LISTEN_ADDR to a non-loopback
// address, exposure is gated on a login password AND served over HTTPS (so
// credentials aren't sent in clear text). Cert is user-provided (LISTEN_CERT/
// LISTEN_KEY) or auto-generated self-signed next to the exe.

var (
	// listenAddr is the configured bind address ("" = default loopback). It's
	// atomic because Settings can rewrite it while handlers read it back.
	listenAddr atomicString
	// listenExposed / listenTLS are decided once in resolveListen before the
	// server starts, then only read — no synchronization needed.
	listenExposed bool // bound to a non-loopback address
	listenTLS     bool // serving HTTPS
)

// newServer builds the HTTP server used by every runApp variant.
//
// The zero-value http.Server has no timeouts at all, which is a slowloris hole
// once the dashboard is exposed: a client can hold connections open mid-header
// forever. WriteTimeout is deliberately left at 0 — /events and /capture are SSE
// streams that must stay open for as long as the operator watches them.
func newServer() *http.Server {
	return &http.Server{
		Handler:           rootHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

// resolveListen computes the bind address, enforcing "exposure requires login",
// and returns the address to listen on plus the URL to open locally.
func resolveListen() (addr, url string) {
	addr = listenAddr.Load()
	if addr == "" {
		addr = "127.0.0.1:5000"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil { // bare host or bare ":port" → default the missing part
		host = strings.Trim(addr, "[]")
		port = "5000"
	}
	if port == "" {
		port = "5000"
	}
	if host == "" {
		host = "0.0.0.0"
	}
	addr = net.JoinHostPort(host, port)

	exposed := !loopbackHost(host)
	if exposed && !authEnabled() {
		log.Printf("[!] LISTEN_ADDR=%s IGNORADO: exponer fuera de localhost requiere login. Activa una contraseña en Ajustes. Usando loopback.", addr)
		host = "127.0.0.1"
		addr = net.JoinHostPort(host, port)
		exposed = false
	}
	listenExposed = exposed
	listenTLS = exposed // HTTPS only when exposed

	scheme := "http"
	if listenTLS {
		scheme = "https"
	}
	browserHost := host
	if host == "0.0.0.0" || host == "::" { // wildcard → reach it locally via loopback
		browserHost = "127.0.0.1"
	}
	return addr, scheme + "://" + net.JoinHostPort(browserHost, port)
}

// tlsListener wraps a plain listener with TLS using a user cert or a self-signed one.
func tlsListener(ln net.Listener) net.Listener {
	var cert tls.Certificate
	cf, kf := os.Getenv("LISTEN_CERT"), os.Getenv("LISTEN_KEY")
	if cf != "" && kf != "" {
		c, err := tls.LoadX509KeyPair(cf, kf)
		if err != nil {
			log.Fatalf("LISTEN_CERT/LISTEN_KEY no se pudieron cargar: %v", err)
		}
		cert = c
	} else {
		c, err := selfSignedCert()
		if err != nil {
			log.Fatalf("no se pudo generar el certificado autofirmado: %v", err)
		}
		cert = c
		log.Println("[+] TLS             certificado autofirmado (el navegador avisará una vez; es esperado)")
	}
	return tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
}

// selfSignedCert loads a cached self-signed cert next to the exe, or generates a
// new one (valid for loopback + every local interface IP + the hostname).
func selfSignedCert() (tls.Certificate, error) {
	cp := filepath.Join(appDir, "efemon-cert.pem")
	kp := filepath.Join(appDir, "efemon-key.pem")
	if c, err := tls.LoadX509KeyPair(cp, kp); err == nil {
		return c, nil
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "eFe Process Monitor"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ipn.IP)
			}
		}
	}
	if hn, err := os.Hostname(); err == nil && hn != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, hn)
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	// The certificate is public by definition, so 0644 is correct.
	// #nosec G306 -- public certificate, intentionally readable
	if err := os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	// The private key goes through writeSecretFile: a 0600 mode is silently
	// ignored on Windows, so the TLS key for the exposed-over-the-network mode was
	// inheriting the directory ACL like any ordinary file.
	if err := writeSecretFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(cp, kp)
}
