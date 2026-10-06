package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// systemd credentials stay out of the service's inherited environment.
// Environment fallback is for development/manual runs, not the supplied service.
var credentialValues map[string]string
var secretNames = []string{"BRAVE_SEARCH_API_KEY", "BACKUP_ENCRYPTION_KEY", "BOOTSTRAP_TOKEN", "INGEST_TOKEN", "PFSENSE_FEED_TOKEN", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GMAIL_USER", "GMAIL_APP_PASSWORD"}

func secret(name string) string {
	if credentialValues != nil {
		return credentialValues[name]
	}
	return os.Getenv(name)
}
func loadCredentials() error {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return nil
	}
	values, e := readCredentialValues(filepath.Join(dir, "secrets.env"))
	if e != nil {
		return e
	}
	credentialValues = values
	return nil
}
func readCredentialValues(path string) (map[string]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("credencial systemd indisponível")
	}
	defer f.Close()
	values := map[string]string{}
	s := bufio.NewScanner(io.LimitReader(f, 65537))
	total := 0
	for s.Scan() {
		line := s.Text()
		total += len(line) + 1
		if total > 65536 {
			return nil, errors.New("arquivo de credenciais excede limite")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("formato de credenciais inválido")
		}
		key = strings.TrimSpace(key)
		known := false
		for _, n := range secretNames {
			if key == n {
				known = true
			}
		}
		if !known {
			return nil, errors.New("nome de credencial não permitido")
		}
		if _, exists := values[key]; exists {
			return nil, errors.New("credencial duplicada")
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("credencial inválida")
		}
		values[key] = value
	}
	if s.Err() != nil {
		return nil, errors.New("falha na leitura de credenciais")
	}
	return values, nil
}
func validateProduction(c Config) error {
	if !strings.HasPrefix(c.PublicURL, "https://") {
		return errors.New("produção exige origem HTTPS; HTTP disponível apenas em -demo")
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil {
		return e
	}
	ip, e := netip.ParseAddr(host)
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("certificado e chave TLS devem ser configurados juntos")
	}
	if e != nil || (!ip.IsLoopback() && (c.TLSCert == "" || c.TLSKey == "")) {
		return errors.New("backend deve escutar em IP loopback atrás de proxy HTTPS")
	}
	for _, n := range []string{"BOOTSTRAP_TOKEN", "INGEST_TOKEN", "PFSENSE_FEED_TOKEN"} {
		v := secret(n)
		if v != "" && !validLocalToken(v) {
			return fmt.Errorf("%s deve conter um segredo aleatório de pelo menos 32 bytes (43 caracteres base64url ou 64 hex)", n)
		}
	}
	if secret("BOOTSTRAP_TOKEN") == "" && (secret("GOOGLE_CLIENT_ID") == "" || secret("GOOGLE_CLIENT_SECRET") == "" || len(c.AllowedEmails) == 0) {
		return errors.New("configure login Google e emails autorizados ou token inicial forte")
	}
	if (secret("GMAIL_USER") == "") != (secret("GMAIL_APP_PASSWORD") == "") {
		return errors.New("configure as duas credenciais Gmail")
	}
	return nil
}

func validLocalToken(v string) bool {
	if len(v) < 43 || len(v) > 256 || strings.ContainsAny(v, " \r\n\t") || strings.Contains(strings.ToUpper(v), "SUBSTITUA") {
		return false
	}
	b, e := hex.DecodeString(v)
	if e != nil {
		b, e = base64.RawURLEncoding.DecodeString(v)
	}
	if e != nil || len(b) < 32 {
		return false
	}
	distinct := map[byte]bool{}
	for _, x := range b {
		distinct[x] = true
	}
	if len(distinct) < 8 {
		return false
	}
	for period := 1; period <= 16; period++ {
		if len(v) < period*3 {
			continue
		}
		repeat := true
		for i := period; i < len(v); i++ {
			if v[i] != v[i%period] {
				repeat = false
				break
			}
		}
		if repeat {
			return false
		}
	}
	return true
}

type rateWindow struct {
	Start time.Time
	Count int
}

func (a *App) takeRate(key string, limit int, window time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	b := a.rates[key]
	if b.Start.IsZero() || now.Sub(b.Start) >= window {
		b = rateWindow{Start: now}
	}
	if b.Count >= limit {
		return false
	}
	if _, exists := a.rates[key]; !exists && len(a.rates) >= 4096 {
		return false
	}
	b.Count++
	a.rates[key] = b
	return true
}
func (a *App) clientIP(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return "invalid"
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return "invalid"
	}
	// Only the local reverse proxy is trusted; use its appended, right-most hop.
	if ip.IsLoopback() && !a.nativeTLS {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			v, e := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1]))
			if e != nil {
				return "invalid"
			}
			return v.Unmap().String()
		}
	}
	return ip.Unmap().String()
}
func (a *App) requestGuard(w http.ResponseWriter, r *http.Request) bool {
	if len(r.URL.RawQuery) > 2048 || len(r.URL.Path) > 2048 {
		http.Error(w, "requisição excede limite", 414)
		return false
	}
	if a.secure() {
		u, _ := url.Parse(a.origin)
		if !strings.EqualFold(r.Host, u.Host) {
			http.Error(w, "host não autorizado", 421)
			return false
		}
		if a.nativeTLS {
			if r.TLS == nil {
				http.Error(w, "TLS obrigatório", 403)
				return false
			}
		} else {
			host, _, e := net.SplitHostPort(r.RemoteAddr)
			ip, pe := netip.ParseAddr(host)
			if e != nil || pe != nil || !ip.IsLoopback() || r.Header.Get("X-Forwarded-Proto") != "https" {
				http.Error(w, "proxy HTTPS local obrigatório", 403)
				return false
			}
		}
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" && (strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/auth/local") {
		http.Error(w, "requisição externa rejeitada", 403)
		return false
	}
	cat := ""
	limit := 0
	switch {
	case strings.HasPrefix(r.URL.Path, "/auth/"):
		cat = "auth"
		limit = 20
	case strings.HasPrefix(r.URL.Path, "/feeds/"):
		cat = "feed"
		limit = 120
	case r.URL.Path == "/api/wazuh":
		cat = "wazuh"
		limit = 600
	case strings.HasPrefix(r.URL.Path, "/api/"):
		cat = "api"
		limit = 180
	}
	if cat != "" && (!a.takeRate("global:"+cat, limit*50, time.Minute) || !a.takeRate(cat+":"+a.clientIP(r), limit, time.Minute)) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "limite de requisições", 429)
		return false
	}
	return true
}
func jsonContent(w http.ResponseWriter, r *http.Request) bool {
	typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || typ != "application/json" {
		http.Error(w, "Content-Type application/json obrigatório", 415)
		return false
	}
	return true
}
func (a *App) sessionName() string {
	if a.secure() {
		return "__Host-multipla_session"
	}
	return "multipla_session"
}
func (a *App) oauthName() string {
	if a.secure() {
		return "__Host-multipla_oauth"
	}
	return "multipla_oauth"
}
func (a *App) cookieValue(r *http.Request, name string) (string, bool) {
	v := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			count++
			v = c.Value
		}
	}
	return v, count == 1 && v != ""
}
func (a *App) securityEvent(action, actor string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.audit(actor, action)
	if e := a.persist(); e != nil {
		a.storageError = "Falha ao gravar auditoria de segurança"
	}
}
func (a *App) feedAllowed(r *http.Request) bool {
	ip, e := netip.ParseAddr(a.clientIP(r))
	if e != nil {
		return false
	}
	for _, p := range a.cfg.FeedAllowed {
		cidr, e := netip.ParsePrefix(p)
		if e == nil && cidr.Contains(ip) {
			return true
		}
	}
	for _, d := range a.cfg.Devices {
		if d.Kind == "pfsense" && d.IP == ip.String() {
			return true
		}
	}
	return false
}

var sensitivePair = regexp.MustCompile(`(?i)(["']?(?:password|passwd|pwd|token|secret|oauth_token|access_token|refresh_token|id_token|client_secret|api[_-]?key|app_password|bootstrap_token|ingest_token|pfsense_feed_token|session[_-]?id|cookie)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)`)
var bearerValue = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`)
var jwtValue = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
var feedURL = regexp.MustCompile(`/feeds/pfsense/[A-Za-z0-9_-]+`)

func redact(s string) string {
	if values := receiverRedactions.Load(); values != nil {
		for _, value := range *values {
			if len(value) >= 8 {
				s = strings.ReplaceAll(s, value, "[REDACTED]")
			}
		}
	}
	if value := googleRedaction.Load(); value != nil && len(*value) >= 8 {
		s = strings.ReplaceAll(s, *value, "[REDACTED]")
	}
	for _, name := range secretNames {
		if name == "GMAIL_USER" || name == "GOOGLE_CLIENT_ID" {
			continue
		}
		v := secret(name)
		if len(v) >= 8 {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	s = sensitivePair.ReplaceAllString(s, "${1}[REDACTED]")
	s = bearerValue.ReplaceAllString(s, "${1}[REDACTED]")
	s = jwtValue.ReplaceAllString(s, "[REDACTED JWT]")
	s = feedURL.ReplaceAllString(s, "/feeds/pfsense/[REDACTED]")
	return strings.ReplaceAll(s, "\x00", "")
}
func regularFile(path string) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return errors.New("arquivo regular obrigatório; links não são permitidos")
	}
	return nil
}

func sanitizeEvent(e Event) Event {
	e.Message = redact(e.Message)
	e.Rule = redact(e.Rule)
	e.Device = redact(e.Device)
	e.Kind = redact(e.Kind)
	e.Detector = redact(e.Detector)
	if e.CEF != nil {
		cef := *e.CEF
		cef.Name = redact(cef.Name)
		cef.EventID = redact(cef.EventID)
		cef.Vendor = redact(cef.Vendor)
		cef.Product = redact(cef.Product)
		cef.Category = redact(cef.Category)
		e.CEF = &cef
	}
	return e
}
func streamEventExport(w http.ResponseWriter, r *http.Request, path string) {
	f, e := os.Open(path)
	if e != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 65536), 262144)
	encoder := json.NewEncoder(w)
	for s.Scan() {
		select {
		case <-r.Context().Done():
			return
		default:
		}
		var ev Event
		if json.Unmarshal(s.Bytes(), &ev) != nil {
			continue
		}
		if encoder.Encode(sanitizeEvent(ev)) != nil {
			return
		}
	}
}
