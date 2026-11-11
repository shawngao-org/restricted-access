package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"restricted-access/internal/access"
	"restricted-access/internal/clientip"
	"restricted-access/internal/config"
	"restricted-access/internal/geo"
	"restricted-access/internal/nonce"
	"restricted-access/internal/token"
)

// Server is the loopback gate. Nginx is the only intended caller.
type Server struct {
	cfg    *config.Config
	loc    geo.Locator
	eval   *access.Evaluator
	ips    *clientip.Resolver
	tokens *token.Issuer
	nonces *nonce.Store
	log    *slog.Logger
	now    func() time.Time
}

func New(cfg *config.Config, loc geo.Locator, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	ips, err := clientip.New(cfg.Server.RealIPHeader, cfg.Server.TrustedProxies)
	if err != nil {
		return nil, err
	}
	eval, err := access.New(cfg.Policy)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		loc:    loc,
		eval:   eval,
		ips:    ips,
		nonces: nonce.New(100000),
		log:    log,
		now:    time.Now,
	}
	issuer, err := token.NewIssuer(cfg.Token.Key, cfg.Gate.Audience, cfg.Token.CodeTTL.Std(), cfg.Token.ClearanceTTL.Std(), func() time.Time {
		return s.Now()
	})
	if err != nil {
		return nil, err
	}
	s.tokens = issuer
	return s, nil
}

func (s *Server) Now() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

func (s *Server) SetNow(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /enter", s.handleEnter)
	mux.HandleFunc("GET /exchange", s.handleExchange)
	mux.HandleFunc("GET /verify", s.handleVerify)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "err", rec)
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			}
		}()
		securityHeaders(w.Header())
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) handleEnter(w http.ResponseWriter, r *http.Request) {
	ref := newRef()
	ip, err := s.ips.ClientIP(r)
	if err != nil {
		s.log.Warn("client ip rejected", "ref", ref, "err", err, "peer", r.RemoteAddr)
		s.writeRegion(w, ref)
		return
	}
	decision := s.decide(ip)
	s.logDecision("enter", ref, ip.String(), decision)
	if decision.Unavailable {
		s.writeUnavailable(w, ref)
		return
	}
	if !decision.Allow {
		s.writeRegion(w, ref)
		return
	}
	if raw, err := r.Cookie(s.cfg.Token.CookieName); err == nil {
		if _, err := s.tokens.Verify(raw.Value, token.TypeClearance, ip, s.cfg.Token.IPv4Prefix, s.cfg.Token.IPv6Prefix); err == nil {
			s.redirect(w, s.cfg.Gate.SuccessPath)
			return
		}
	}
	code, claims, err := s.tokens.Issue(token.TypeCode, ip, decision.Country)
	if err != nil {
		s.log.Error("issue code", "ref", ref, "err", err)
		s.writeUnavailable(w, ref)
		return
	}
	if err := s.nonces.Put(claims.JTI, time.Unix(claims.EXP, 0), s.Now()); err != nil {
		s.log.Error("store code", "ref", ref, "err", err)
		s.writeUnavailable(w, ref)
		return
	}
	loc, err := appendQuery(s.cfg.Gate.CallbackURL, s.cfg.Token.CodeQuery, code)
	if err != nil {
		s.log.Error("callback url", "ref", ref, "err", err)
		s.writeUnavailable(w, ref)
		return
	}
	s.redirect(w, loc)
}

func (s *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	ref := newRef()
	ip, err := s.ips.ClientIP(r)
	if err != nil {
		s.log.Warn("client ip rejected", "ref", ref, "err", err, "peer", r.RemoteAddr)
		s.writeRegion(w, ref)
		return
	}
	if s.cfg.Token.CookieSecure && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "http") {
		s.log.Error("refusing secure cookie on http", "ref", ref)
		s.writePage(w, http.StatusInternalServerError, pageData{
			Lang:    s.cfg.BlockPage.Lang,
			Eyebrow: "Configuration Error",
			Title:   "Verification endpoint does not use HTTPS",
			Message: "Clearance credentials can only be issued over HTTPS. Please enable TLS on the target site, or disable `cookie_secure` only when debugging locally.",
			English: "The clearance cookie requires HTTPS.",
			Ref:     ref,
		})
		return
	}
	decision := s.decide(ip)
	s.logDecision("exchange", ref, ip.String(), decision)
	if decision.Unavailable {
		s.writeUnavailable(w, ref)
		return
	}
	raw := r.URL.Query().Get(s.cfg.Token.CodeQuery)
	claims, err := s.tokens.Verify(raw, token.TypeCode, ip, s.cfg.Token.IPv4Prefix, s.cfg.Token.IPv6Prefix)
	if err != nil {
		s.log.Info("exchange rejected", "ref", ref, "ip", ip.String(), "reason", err.Error())
		s.writeInvalid(w, ref)
		return
	}
	if !decision.Allow {
		s.nonces.Consume(claims.JTI, s.Now())
		s.writeRegion(w, ref)
		return
	}
	if !s.nonces.Consume(claims.JTI, s.Now()) {
		s.log.Info("exchange rejected", "ref", ref, "ip", ip.String(), "reason", "replay")
		s.writeInvalid(w, ref)
		return
	}
	clearance, _, err := s.tokens.Issue(token.TypeClearance, ip, decision.Country)
	if err != nil {
		s.log.Error("issue clearance", "ref", ref, "err", err)
		s.writeUnavailable(w, ref)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.Token.CookieName,
		Value:    clearance,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.Token.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.Token.ClearanceTTL.Std().Seconds()),
	})
	s.redirect(w, s.cfg.Gate.SuccessPath)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	ref := newRef()
	ip, err := s.ips.ClientIP(r)
	if err != nil {
		s.log.Warn("verify rejected", "ref", ref, "reason", "client_ip", "err", err)
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	decision := s.decide(ip)
	if !decision.Allow {
		s.log.Info("verify rejected", "ref", ref, "ip", ip.String(), "reason", decision.Reason)
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	cookie, err := r.Cookie(s.cfg.Token.CookieName)
	if err != nil {
		s.log.Info("verify rejected", "ref", ref, "ip", ip.String(), "reason", "missing_cookie")
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	if _, err := s.tokens.Verify(cookie.Value, token.TypeClearance, ip, s.cfg.Token.IPv4Prefix, s.cfg.Token.IPv6Prefix); err != nil {
		s.log.Info("verify rejected", "ref", ref, "ip", ip.String(), "reason", err.Error())
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.loc != nil && s.loc.Ready() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("database unavailable\n"))
}

func (s *Server) decide(ip netip.Addr) access.Decision {
	rec, err := s.loc.Locate(ip)
	return s.eval.Decide(ip, rec, err)
}

func (s *Server) logDecision(op, ref, ip string, d access.Decision) {
	s.log.Info(op, "ref", ref, "ip", ip, "allow", d.Allow, "reason", d.Reason, "country", d.Country)
}

func (s *Server) writeRegion(w http.ResponseWriter, ref string) {
	eyebrow := "Regional restrictions"
	if s.cfg.BlockPage.SiteName != "" {
		eyebrow = s.cfg.BlockPage.SiteName
	}
	s.writePage(w, http.StatusForbidden, pageData{
		Lang:    s.cfg.BlockPage.Lang,
		Eyebrow: eyebrow,
		Title:   s.cfg.BlockPage.Title,
		Message: s.cfg.BlockPage.Message,
		English: s.cfg.BlockPage.English,
		Ref:     ref,
	})
}

func (s *Server) writeUnavailable(w http.ResponseWriter, ref string) {
	s.writePage(w, http.StatusServiceUnavailable, pageData{
		Lang:    s.cfg.BlockPage.Lang,
		Eyebrow: "Access Not Yet Available",
		Title:   "Unable to Determine Access Region",
		Message: "Regional data is currently unavailable. Access is denied until your network location can be verified.",
		English: "Access is denied until the region check can be completed.",
		Ref:     ref,
	})
}

func (s *Server) writeInvalid(w http.ResponseWriter, ref string) {
	s.writePage(w, http.StatusForbidden, pageData{
		Lang:     s.cfg.BlockPage.Lang,
		Eyebrow:  "Re-entry Required",
		Title:    "Access Credentials Invalid",
		Message:  "This access link has already been used, has expired, or does not match your current network address. Please re-enter via the main site so your region can be verified again.",
		English:  "This access link has expired or does not match the current network address.",
		Link:     s.cfg.Gate.EntryPath,
		LinkText: "Re-enter",
		Ref:      ref,
	})
}

func (s *Server) writePage(w http.ResponseWriter, status int, data pageData) {
	var buf strings.Builder
	if err := pageTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(buf.String()))
}

func (s *Server) redirect(w http.ResponseWriter, loc string) {
	w.Header().Set("Location", loc)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusFound)
	_, _ = w.Write([]byte("redirect\n"))
}

func securityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
}

func appendQuery(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", err
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func newRef() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "RA-UNKNOWN"
	}
	return "RA-" + strings.ToUpper(hex.EncodeToString(buf))
}
