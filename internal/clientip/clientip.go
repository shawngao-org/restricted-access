package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Resolver extracts the client address. Headers are honored only when the TCP
// peer is a trusted proxy; otherwise a caller can spoof X-Real-IP.
type Resolver struct {
	header  string
	trusted []netip.Prefix
}

func New(header string, trusted []string) (*Resolver, error) {
	if header == "" {
		return nil, fmt.Errorf("real IP header is empty")
	}
	prefixes := make([]netip.Prefix, 0, len(trusted))
	for _, raw := range trusted {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", raw, err)
		}
		prefixes = append(prefixes, p)
	}
	return &Resolver{header: header, trusted: prefixes}, nil
}

// ClientIP returns the address that must be used for both geolocation and
// token binding. A missing or malformed header from a trusted proxy is an
// error, not a fallback to the proxy's own address.
func (r *Resolver) ClientIP(req *http.Request) (netip.Addr, error) {
	peer, err := peerAddr(req.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	if !r.isTrusted(peer) {
		return peer, nil
	}
	raw := strings.TrimSpace(req.Header.Get(r.header))
	if raw == "" {
		return netip.Addr{}, fmt.Errorf("trusted proxy did not send %s", r.header)
	}
	if strings.Contains(raw, ",") || strings.ContainsAny(raw, " \t") {
		return netip.Addr{}, fmt.Errorf("rejected ambiguous %s", r.header)
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.IsValid() || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("rejected invalid %s", r.header)
	}
	return addr.Unmap(), nil
}

func (r *Resolver) isTrusted(ip netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func peerAddr(remote string) (netip.Addr, error) {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsValid() || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid peer address")
	}
	return addr.Unmap(), nil
}
