package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const version = 1

type Type string

const (
	TypeCode      Type = "code"
	TypeClearance Type = "clearance"
)

// Claims is the signed payload. The MAC covers the exact encoded bytes, so
// there is no algorithm field an attacker can switch.
type Claims struct {
	Version int    `json:"v"`
	Type    string `json:"typ"`
	IP      string `json:"ip"`
	IAT     int64  `json:"iat"`
	EXP     int64  `json:"exp"`
	Aud     string `json:"aud"`
	JTI     string `json:"jti"`
	Country string `json:"cc,omitempty"`
}

type VerifyError struct{ Reason string }

func (e *VerifyError) Error() string { return e.Reason }

type Issuer struct {
	key          []byte
	audience     string
	codeTTL      time.Duration
	clearanceTTL time.Duration
	skew         time.Duration
	now          func() time.Time
}

func NewIssuer(key []byte, audience string, codeTTL, clearanceTTL time.Duration, now func() time.Time) (*Issuer, error) {
	if len(key) < 32 {
		return nil, errors.New("signing key is too short")
	}
	if audience == "" {
		return nil, errors.New("audience is empty")
	}
	if now == nil {
		now = time.Now
	}
	return &Issuer{
		key:          append([]byte(nil), key...),
		audience:     audience,
		codeTTL:      codeTTL,
		clearanceTTL: clearanceTTL,
		skew:         30 * time.Second,
		now:          now,
	}, nil
}

func (i *Issuer) Issue(typ Type, ip netip.Addr, country string) (string, Claims, error) {
	if typ != TypeCode && typ != TypeClearance {
		return "", Claims{}, errors.New("unknown token type")
	}
	if !ip.IsValid() {
		return "", Claims{}, errors.New("invalid ip")
	}
	jti, err := randomJTI()
	if err != nil {
		return "", Claims{}, err
	}
	now := i.now()
	claims := Claims{
		Version: version,
		Type:    string(typ),
		IP:      ip.Unmap().String(),
		IAT:     now.Unix(),
		EXP:     now.Add(i.ttl(typ)).Unix(),
		Aud:     i.audience,
		JTI:     jti,
		Country: country,
	}
	raw, err := encode(i.key, claims)
	if err != nil {
		return "", Claims{}, err
	}
	return raw, claims, nil
}

// Verify checks the MAC before trusting any claim, then enforces type, audience,
// lifetime, and IP binding. A code cannot be presented as a clearance cookie.
func (i *Issuer) Verify(raw string, typ Type, client netip.Addr, v4Bits, v6Bits int) (Claims, error) {
	if len(raw) == 0 || len(raw) > 2048 {
		return Claims{}, &VerifyError{Reason: "malformed"}
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return Claims{}, &VerifyError{Reason: "malformed"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > 1024 {
		return Claims{}, &VerifyError{Reason: "malformed"}
	}
	mac, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(mac, sign(i.key, payload)) {
		return Claims{}, &VerifyError{Reason: "bad_mac"}
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	var claims Claims
	if err := dec.Decode(&claims); err != nil || dec.More() {
		return Claims{}, &VerifyError{Reason: "malformed"}
	}
	if claims.Version != version {
		return Claims{}, &VerifyError{Reason: "version"}
	}
	if claims.Type != string(typ) {
		return Claims{}, &VerifyError{Reason: "type"}
	}
	if claims.Aud != i.audience || claims.JTI == "" {
		return Claims{}, &VerifyError{Reason: "audience"}
	}
	now := i.now()
	issued := time.Unix(claims.IAT, 0)
	expires := time.Unix(claims.EXP, 0)
	if claims.IAT <= 0 || claims.EXP <= claims.IAT || issued.After(now.Add(i.skew)) {
		return Claims{}, &VerifyError{Reason: "not_yet_valid"}
	}
	if !now.Before(expires) {
		return Claims{}, &VerifyError{Reason: "expired"}
	}
	if expires.Sub(issued) > i.ttl(typ)+i.skew {
		return Claims{}, &VerifyError{Reason: "lifetime"}
	}
	tokenIP, err := netip.ParseAddr(claims.IP)
	if err != nil || !samePrefix(tokenIP, client, v4Bits, v6Bits) {
		return Claims{}, &VerifyError{Reason: "ip_mismatch"}
	}
	return claims, nil
}

func (i *Issuer) ttl(typ Type) time.Duration {
	if typ == TypeCode {
		return i.codeTTL
	}
	return i.clearanceTTL
}

func encode(key []byte, claims Claims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	mac := sign(key, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

func sign(key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(payload)
	return m.Sum(nil)
}

func samePrefix(tokenIP, client netip.Addr, v4Bits, v6Bits int) bool {
	if !tokenIP.IsValid() || !client.IsValid() {
		return false
	}
	tokenIP = tokenIP.Unmap()
	client = client.Unmap()
	if tokenIP.Is4() != client.Is4() {
		return false
	}
	bits := v6Bits
	if tokenIP.Is4() {
		bits = v4Bits
	}
	if bits <= 0 {
		return false
	}
	prefix, err := tokenIP.Prefix(bits)
	if err != nil {
		return false
	}
	return prefix.Contains(client)
}

func randomJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
