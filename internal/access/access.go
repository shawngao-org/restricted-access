package access

import (
	"net/netip"
	"strings"

	"restricted-access/internal/config"
	"restricted-access/internal/geo"
)

// Decision is the only thing the HTTP layer needs. Allow is false unless a
// rule explicitly permits the address.
type Decision struct {
	Allow       bool
	Unavailable bool
	Reason      string
	Country     string
}

type Evaluator struct {
	policy      config.PolicyConfig
	denyCountry map[string]struct{}
	denySub     map[string]struct{}
	alwaysDeny  []netip.Prefix
	alwaysAllow []netip.Prefix
}

func New(policy config.PolicyConfig) (*Evaluator, error) {
	e := &Evaluator{
		policy:      policy,
		denyCountry: setOf(policy.DenyCountries),
		denySub:     setOf(policy.DenySubdivisions),
	}
	var err error
	if e.alwaysDeny, err = prefixes(policy.AlwaysDenyIPs); err != nil {
		return nil, err
	}
	if e.alwaysAllow, err = prefixes(policy.AlwaysAllowIPs); err != nil {
		return nil, err
	}
	return e, nil
}

// Decide applies the blacklist after explicit IP overrides. Database failures
// are unavailable, not allowed, unless the address is an operator break-glass IP.
func (e *Evaluator) Decide(ip netip.Addr, rec geo.Record, locErr error) Decision {
	if !ip.IsValid() {
		return Decision{Reason: "invalid_ip"}
	}
	ip = ip.Unmap()
	if contains(e.alwaysDeny, ip) {
		return Decision{Reason: "always_deny", Country: rec.Country}
	}
	if isNonPublic(ip) {
		if e.policy.PrivateIPAction == "allow" {
			return Decision{Allow: true, Reason: "private_ip_allow"}
		}
		return Decision{Reason: "private_ip"}
	}
	if contains(e.alwaysAllow, ip) {
		return Decision{Allow: true, Reason: "always_allow", Country: rec.Country}
	}
	if locErr != nil {
		if locErr == geo.ErrStale {
			return Decision{Unavailable: true, Reason: "database_stale"}
		}
		return Decision{Unavailable: true, Reason: "database_unavailable"}
	}
	if rec.Country == "" && rec.RegisteredCountry == "" && rec.RepresentedCountry == "" {
		if e.policy.UnknownAction == "allow" {
			return Decision{Allow: true, Reason: "unknown_allow"}
		}
		return Decision{Reason: "unknown_location"}
	}
	if rec.Country != "" && has(e.denyCountry, rec.Country) {
		return Decision{Reason: "country_denied", Country: rec.Country}
	}
	if e.policy.CheckRegisteredCountry && rec.RegisteredCountry != "" && has(e.denyCountry, rec.RegisteredCountry) {
		return Decision{Reason: "registered_country_denied", Country: rec.RegisteredCountry}
	}
	if e.policy.CheckRepresentedCountry && rec.RepresentedCountry != "" && has(e.denyCountry, rec.RepresentedCountry) {
		return Decision{Reason: "represented_country_denied", Country: rec.RepresentedCountry}
	}
	if rec.Country != "" {
		for _, sub := range rec.Subdivisions {
			if has(e.denySub, rec.Country+"-"+sub) {
				return Decision{Reason: "subdivision_denied", Country: rec.Country}
			}
		}
	}
	return Decision{Allow: true, Reason: "allowed", Country: rec.Country}
}

func isNonPublic(ip netip.Addr) bool {
	return !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast()
}

func contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func has(set map[string]struct{}, key string) bool {
	_, ok := set[strings.ToUpper(key)]
	return ok
}

func setOf(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		out[strings.ToUpper(item)] = struct{}{}
	}
	return out
}

func prefixes(items []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		var p netip.Prefix
		var err error
		if strings.Contains(item, "/") {
			p, err = netip.ParsePrefix(item)
		} else {
			var addr netip.Addr
			addr, err = netip.ParseAddr(item)
			if err == nil {
				addr = addr.Unmap()
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				p, err = addr.Prefix(bits)
			}
		}
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
