package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecurityUnauthenticatedRouteMatrix(t *testing.T) {
	a := testApp(t)
	h := a.routes()
	for _, c := range []struct{ method, path string }{{"GET", "/api/snapshot"}, {"GET", "/api/export?day=2026-10-03"}, {"PUT", "/api/config"}, {"PUT", "/api/rules"}, {"POST", "/api/blocks"}, {"DELETE", "/api/blocks/198.51.100.2"}, {"POST", "/api/mail/test"}, {"POST", "/api/activity"}, {"POST", "/auth/logout"}, {"POST", "/api/demo"}, {"POST", "/api/wazuh"}, {"GET", "/feeds/pfsense/unknown"}} {
		r := testRequest(c.method, c.path, strings.NewReader(`{}`))
		r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "forged"})
		r.Header.Set("Origin", a.origin)
		r.Header.Set("X-CSRF-Token", "forged")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Errorf("%s %s: got %d", c.method, c.path, w.Code)
		}
	}
}
func TestSecurityHostAndProxyBoundary(t *testing.T) {
	a := testApp(t)
	a.origin = "https://siem.example.com"
	h := a.routes()
	for _, c := range []struct {
		host, addr, proto string
		want              int
	}{{"evil.example", "127.0.0.1:1000", "https", 421}, {"siem.example.com", "198.51.100.1:1000", "https", 403}, {"siem.example.com", "127.0.0.1:1000", "http", 403}, {"siem.example.com", "127.0.0.1:1000", "https", 200}} {
		r := testRequest("GET", "/healthz", nil)
		r.Host = c.host
		r.RemoteAddr = c.addr
		r.Header.Set("X-Forwarded-Proto", c.proto)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%+v: %d", c, w.Code)
		}
	}
}
func TestSecurityNativeTLSDoesNotTrustForwardedHeaders(t *testing.T) {
	a := testApp(t)
	a.origin = "https://siem.example.com"
	a.nativeTLS = true
	r := testRequest("GET", "/healthz", nil)
	r.Host = "siem.example.com"
	r.RemoteAddr = "198.51.100.2:1000"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", "192.168.1.1")
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("plaintext accepted")
	}
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("native TLS rejected")
	}
	r.RemoteAddr = "127.0.0.1:1000"
	if a.clientIP(r) != "127.0.0.1" {
		t.Fatal("spoofed native forwarded source")
	}
}
func TestSecurityBootstrapReplayExpirationAndThrottle(t *testing.T) {
	a := testApp(t)
	t.Setenv("BOOTSTRAP_TOKEN", "private-initial-token")
	send := func(token string) *httptest.ResponseRecorder {
		r := testRequest("POST", "/auth/local", strings.NewReader("token="+token))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", a.origin)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		return w
	}
	if send("private-initial-token").Code != 303 {
		t.Fatal("initial login failed")
	}
	if send("private-initial-token").Code != 403 {
		t.Fatal("initial token replay accepted")
	}
	a.bootstrapUsed = false
	a.bootAt = time.Now().Add(-16 * time.Minute)
	if send("private-initial-token").Code != 403 {
		t.Fatal("expired bootstrap accepted")
	}
	for i := 0; i < 25; i++ {
		w := send("bad")
		if i >= 20 && w.Code != 429 {
			t.Fatal("login throttle absent", w.Code)
		}
	}
}
func TestSecurityIdleTimeoutAndDuplicateCookies(t *testing.T) {
	a := testApp(t)
	a.sessions["session"] = Session{"", "admin@gmail.com", "csrf", time.Now().Add(time.Hour)}
	a.active["session"] = time.Now().Add(-16 * time.Minute)
	r := testRequest("GET", "/api/snapshot", nil)
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "session"})
	if _, ok := a.session(r); ok {
		t.Fatal("idle session accepted")
	}
	a.sessions["session"] = Session{"", "admin@gmail.com", "csrf", time.Now().Add(time.Hour)}
	a.active["session"] = time.Now()
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "attacker"})
	if _, ok := a.session(r); ok {
		t.Fatal("duplicate cookies accepted")
	}
}
func TestSecuritySessionRotationAndHostCookie(t *testing.T) {
	a := testApp(t)
	a.origin = "https://siem.example.com"
	a.sessions["old"] = Session{"", "admin@gmail.com", "old-csrf", time.Now().Add(time.Hour)}
	r := testRequest("GET", "https://siem.example.com/", nil)
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "old"})
	w := httptest.NewRecorder()
	a.newSession(w, r, "admin@gmail.com")
	if _, ok := a.sessions["old"]; ok {
		t.Fatal("session fixation: old token survived")
	}
	c := w.Result().Cookies()[0]
	if c.Name != "__Host-multipla_session" || !c.Secure || !c.HttpOnly || c.Domain != "" || c.Path != "/" || c.MaxAge != 0 {
		t.Fatalf("unsafe cookie: %+v", c)
	}
}
func TestSecurityRedactionBeforePersistence(t *testing.T) {
	a := testApp(t)
	known := strings.Repeat("private-seed-", 5)
	t.Setenv("GOOGLE_CLIENT_SECRET", known)
	raw := `Failed password from 198.51.100.9 password="secret with spaces" api_key=secret-api token=generic-token secret=generic-secret Authorization: Bearer leaked.token.value {"refresh_token":"refresh-value"} /feeds/pfsense/private-feed-token ` + known
	a.ingest(Device{"PVE", "192.168.1.2", "proxmox"}, raw)
	b, e := os.ReadFile(a.journalPath(time.Now()))
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"secret with spaces", "secret-api", "generic-token", "generic-secret", "leaked.token.value", "refresh-value", "private-feed-token", known} {
		if strings.Contains(string(b), s) {
			t.Fatalf("credential persisted: %s", s)
		}
	}
	if !strings.Contains(string(b), "198.51.100.9") {
		t.Fatal("source IP lost")
	}
}
func TestSecuritySecretNotInSnapshot(t *testing.T) {
	a := testApp(t)
	value := strings.Repeat("credential-", 5)
	for _, name := range secretNames {
		if name != "GMAIL_USER" && name != "GOOGLE_CLIENT_ID" {
			t.Setenv(name, value)
		}
	}
	a.sessions["session"] = Session{"", "admin@gmail.com", "csrf", time.Now().Add(time.Hour)}
	r := testRequest("GET", "/api/snapshot", nil)
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "session"})
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), value) {
		t.Fatal("secret in snapshot or failed request")
	}
}
func TestSecurityJSONAndCrossOrigin(t *testing.T) {
	a := testApp(t)
	a.sessions["s"] = Session{"", "admin@gmail.com", "csrf", time.Now().Add(time.Hour)}
	r := testRequest("POST", "/api/blocks", strings.NewReader(`{"ip":"198.51.100.1","reason":"test"}`))
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "s"})
	r.Header.Set("Origin", a.origin)
	r.Header.Set("X-CSRF-Token", "csrf")
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal("content type bypass", w.Code)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-site bypass")
	}
}
func TestSecurityGoogleRedirectDoesNotForwardSecret(t *testing.T) {
	hits := 0
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer dest.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dest.URL, 307) }))
	defer src.Close()
	c := &http.Client{CheckRedirect: client.CheckRedirect}
	r, e := c.PostForm(src.URL, map[string][]string{"client_secret": {"never-forward-this"}})
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if hits != 0 || r.StatusCode != 307 {
		t.Fatal("outbound redirect followed")
	}
}
func TestSecurityProductionFailClosed(t *testing.T) {
	a := testApp(t)
	a.cfg.PublicURL = "https://siem.example.com"
	t.Setenv("BOOTSTRAP_TOKEN", token())
	if validateProduction(a.cfg) != nil {
		t.Fatal("valid isolated config rejected")
	}
	a.cfg.Listen = "0.0.0.0:8080"
	if validateProduction(a.cfg) == nil {
		t.Fatal("public plaintext listener accepted")
	}
	a.cfg.TLSCert = "cert"
	a.cfg.TLSKey = "key"
	if validateProduction(a.cfg) != nil {
		t.Fatal("native HTTPS config rejected")
	}
	t.Setenv("BOOTSTRAP_TOKEN", "weak")
	if validateProduction(a.cfg) == nil {
		t.Fatal("weak initial credential accepted")
	}
	a.cfg.PublicURL = "http://127.0.0.1:8443"
	if validateProduction(a.cfg) == nil {
		t.Fatal("production HTTP accepted")
	}
}
func TestSecurityFeedRequiresAllowedSource(t *testing.T) {
	a := testApp(t)
	t.Setenv("PFSENSE_FEED_TOKEN", "feed-secret")
	r := testRequest("GET", "/feeds/pfsense/feed-secret", nil)
	r.RemoteAddr = "198.51.100.20:1000"
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("feed accepts stolen token from unapproved source")
	}
	a.cfg.FeedAllowed = []string{"198.51.100.20/32"}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("configured feed source rejected")
	}
}
func TestSecurityPathTraversalAndPublicFiles(t *testing.T) {
	a := testApp(t)
	for _, path := range []string{"/config.json", "/secrets.env", "/state.json", "/main.go", "/.git/config", "/web/../../secrets.env"} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, testRequest("GET", path, nil))
		if w.Code == 200 {
			t.Fatalf("public file: %s", path)
		}
	}
	a.sessions["s"] = Session{"", "admin@gmail.com", "csrf", time.Now().Add(time.Hour)}
	r := testRequest("GET", "/api/export?day=../../secrets.env", nil)
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "s"})
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("export traversal accepted")
	}
}
func TestSecurityCertificateUniqueAndBoundToHost(t *testing.T) {
	cert, key, fp, e := makeCertificate("siem.example.com")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tls.X509KeyPair(cert, key); e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(cert)
	x, e := x509.ParseCertificate(block.Bytes)
	if e != nil || x.VerifyHostname("siem.example.com") != nil || x.VerifyHostname("evil.example") == nil || len(fp) != 64 {
		t.Fatal("certificate host/identity failed")
	}
	cert2, key2, fp2, e := makeCertificate("192.168.1.20")
	if e != nil || fp == fp2 || string(key) == string(key2) || string(cert) == string(cert2) {
		t.Fatal("shared installation key")
	}
	block, _ = pem.Decode(cert2)
	x, _ = x509.ParseCertificate(block.Bytes)
	if x.VerifyHostname("192.168.1.20") != nil {
		t.Fatal("IP SAN missing")
	}
}
func TestSecurityCredentialWhitelist(t *testing.T) {
	dir := t.TempDir()
	prior := credentialValues
	defer func() { credentialValues = prior }()
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	path := filepath.Join(dir, "secrets.env")
	os.WriteFile(path, []byte("BOOTSTRAP_TOKEN=loaded-private-token\nLD_PRELOAD=/tmp/malware\n"), 0600)
	if loadCredentials() == nil {
		t.Fatal("unknown credential accepted")
	}
	os.WriteFile(path, []byte("BOOTSTRAP_TOKEN=loaded-private-token\n"), 0600)
	if e := loadCredentials(); e != nil {
		t.Fatal(e)
	}
	if secret("BOOTSTRAP_TOKEN") != "loaded-private-token" {
		t.Fatal("credential missing")
	}
	t.Setenv("INGEST_TOKEN", "inherited-value")
	if secret("INGEST_TOKEN") != "" {
		t.Fatal("environment fallback with systemd credentials")
	}
}
func FuzzSecurityRedactionAndInput(f *testing.F) {
	f.Add("Failed password from 198.51.100.1 password=secret")
	f.Add("filterlog: malformed")
	f.Add(`{"password":"a"}`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 65536 {
			t.Skip()
		}
		_ = redact(s)
		_ = sourceIP(s, "pfsense")
		_ = sourceIP(s, "proxmox")
		var e Event
		if json.Unmarshal([]byte(s), &e) == nil {
			_, _ = json.Marshal(e)
		}
	})
}
