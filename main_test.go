package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	c := Config{Listen: "127.0.0.1:8080", Syslog: "127.0.0.1:5514", PublicURL: "http://127.0.0.1:8080", DataDir: dir, RetentionDays: 7, BlockMinutes: 60, MailMinLevel: 10, AllowedEmails: []string{"admin@gmail.com"}, Devices: []Device{{"Firewall", "192.168.1.1", "pfsense"}}}
	path := filepath.Join(dir, "config.json")
	if e := atomicJSON(path, c); e != nil {
		t.Fatal(e)
	}
	a, e := newApp(c, path, false)
	if e != nil {
		t.Fatal(e)
	}
	return a
}

type roundTrip func(*http.Request) (*http.Response, error)

func testRequest(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	r.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(path, "/feeds/") {
		r.RemoteAddr = "192.168.1.1:12345"
	}
	return r
}

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestGoogleFlowAndRevocation(t *testing.T) {
	a := testApp(t)
	t.Setenv("GOOGLE_CLIENT_ID", "client")
	t.Setenv("GOOGLE_CLIENT_SECRET", "secret")
	original := client
	defer func() { client = original }()
	client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		body := `{"access_token":"google-token"}`
		if strings.Contains(r.URL.Host, "openidconnect") {
			if r.Header.Get("Authorization") != "Bearer google-token" {
				t.Fatal("missing Google access token")
			}
			body = `{"sub":"123","email":"admin@gmail.com","email_verified":true}`
		} else {
			if e := r.ParseForm(); e != nil || r.Form.Get("code_verifier") == "" {
				t.Fatal("missing PKCE verifier")
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	h := a.routes()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, testRequest("GET", "/auth/google", nil))
	u, _ := url.Parse(w.Header().Get("Location"))
	if u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("missing PKCE")
	}
	var stateCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "multipla_oauth" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("state cookie missing")
	}
	r := testRequest("GET", "/auth/callback?code=code&state="+u.Query().Get("state"), nil)
	r.AddCookie(stateCookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "multipla_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly {
		t.Fatal("session missing or not HttpOnly")
	}
	r = testRequest("GET", "/api/snapshot", nil)
	r.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("Google session failed")
	}
	a.cfg.AllowedEmails = nil
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("removed Google user not revoked")
	}
}
func TestBootstrapAndDemoLogin(t *testing.T) {
	a := testApp(t)
	t.Setenv("BOOTSTRAP_TOKEN", "local-secret")
	for _, demo := range []bool{false, true} {
		a.demo = demo
		body := "token=local-secret"
		if demo {
			body = "token="
		}
		r := testRequest("POST", "/auth/local", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", a.origin)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 303 || w.Header().Get("Location") != "/" {
			t.Fatal("login redirect failed", w.Code)
		}
		if len(w.Result().Cookies()) == 0 {
			t.Fatal("login cookie missing")
		}
	}
}
func TestSourceParsing(t *testing.T) {
	cases := []struct{ raw, kind, want string }{
		{"sshd: Failed password for root from 203.0.113.20 port 443 ssh2", "proxmox", "203.0.113.20"},
		{"pvedaemon authentication failure; rhost=2001:db8::5 user=root", "proxmox", "2001:db8::5"},
		{"filterlog: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.1,192.168.1.2,111,22,0,S", "pfsense", "203.0.113.1"},
		{"filterlog: 5,,,1000000103,igb0,match,pass,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.1,192.168.1.2,111,22,0,S", "pfsense", ""},
		{"filterlog: malformed", "pfsense", ""},
		{"filterlog: 5,,,1,igb0,match,block,in,6,0x0,0,64,tcp,6,60,2001:db8::3,2001:db8::4,123,22,0,S", "pfsense", "2001:db8::3"},
	}
	for _, c := range cases {
		if got := sourceIP(c.raw, c.kind); got != c.want {
			t.Errorf("%s: %q != %q", c.raw, got, c.want)
		}
	}
}
func TestCorrelationAndDurableReplay(t *testing.T) {
	a := testApp(t)
	d := Device{"Proxmox", "192.168.1.10", "proxmox"}
	for i := 0; i < 4; i++ {
		a.ingest(d, "Failed password from 203.0.113.22")
	}
	if len(a.state.Blocks) != 0 {
		t.Fatal("blocked below threshold")
	}
	a.ingest(d, "Failed password from 203.0.113.22")
	a.ingest(d, "Failed password from 203.0.113.22")
	alerts := 0
	for _, e := range a.events {
		if e.Alert {
			alerts++
		}
	}
	if alerts != 1 {
		t.Fatalf("want 1 alert got %d", alerts)
	}
	if a.state.Blocks["203.0.113.22"].Mode != "simulation" {
		t.Fatal("simulation missing")
	}
	b, e := newApp(a.cfg, a.configPath, false)
	if e != nil {
		t.Fatal(e)
	}
	if len(b.events) != 7 || len(b.state.Blocks) != 1 {
		t.Fatal("state not replayed")
	}
}
func TestBlockProtectionsAndFeed(t *testing.T) {
	a := testApp(t)
	a.cfg.Protected = []string{"203.0.113.0/24"}
	for _, ip := range []string{"192.168.1.5", "127.0.0.1", "169.254.1.1", "::1", "203.0.113.20", "::ffff:192.168.1.2", "not-an-ip"} {
		if a.block(ip, "test", "test") == nil {
			t.Fatalf("protected %s accepted", ip)
		}
	}
	t.Setenv("PFSENSE_FEED_TOKEN", "secret")
	a.cfg.AutoBlock = true
	if e := a.block("198.51.100.4", "test", "test"); e != nil {
		t.Fatal(e)
	}
	h := a.routes()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, testRequest("GET", "/feeds/pfsense/secret", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "198.51.100.4") {
		t.Fatal(w.Code, w.Body.String())
	}
	a.cfg.AutoBlock = false
	w = httptest.NewRecorder()
	h.ServeHTTP(w, testRequest("GET", "/feeds/pfsense/secret", nil))
	if strings.Contains(w.Body.String(), "198.51.100.4") {
		t.Fatal("disabled feed leaked")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, testRequest("GET", "/feeds/pfsense/wrong", nil))
	if w.Code != 401 {
		t.Fatal("unauthenticated feed")
	}
}
func TestAuthCSRFAndOAuthState(t *testing.T) {
	a := testApp(t)
	h := a.routes()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, testRequest("GET", "/api/snapshot", nil))
	if w.Code != 401 {
		t.Fatal("public snapshot")
	}
	a.sessions["s"] = Session{"", "admin@gmail.com", "csrf", time.Now().Add(time.Hour)}
	for _, origin := range []string{"", "https://evil.example"} {
		r := testRequest("POST", "/api/blocks", strings.NewReader(`{"ip":"198.51.100.9","reason":"test"}`))
		r.AddCookie(&http.Cookie{Name: "multipla_session", Value: "s"})
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", "csrf")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("CSRF accepted")
		}
	}
	r := testRequest("POST", "/api/blocks", strings.NewReader(`{"ip":"198.51.100.9","reason":"test"}`))
	r.AddCookie(&http.Cookie{Name: "multipla_session", Value: "s"})
	r.Header.Set("Origin", a.origin)
	r.Header.Set("X-CSRF-Token", "csrf")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, testRequest("GET", "/auth/callback?state=forged&code=bad", nil))
	if w.Code != 403 {
		t.Fatal("invalid OAuth state accepted")
	}
	a.sessions["s"] = Session{"", "admin@gmail.com", "csrf", time.Now().Add(-time.Minute)}
	r = testRequest("GET", "/api/snapshot", nil)
	r.AddCookie(&http.Cookie{Name: "multipla_session", Value: "s"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("expired session accepted")
	}
}
func TestRuleValidationAndWindow(t *testing.T) {
	a := testApp(t)
	rs := defaults()
	rs[0].Pattern = "["
	if validateRules(rs) == nil {
		t.Fatal("invalid regex")
	}
	rs = defaults()
	rs[0].Threshold = 0
	if validateRules(rs) == nil {
		t.Fatal("invalid threshold")
	}
	a.state.Rules = []Rule{{"test", "test", "any", "failed", 2, 60, 10, false, true}}
	key := "test|192.168.1.10|"
	a.counters[key] = bucket{Times: []time.Time{time.Now().Add(-time.Hour)}}
	a.ingest(Device{"Proxmox", "192.168.1.10", "proxmox"}, "failed")
	for _, e := range a.events {
		if e.Alert {
			t.Fatal("expired event correlated")
		}
	}
}
func TestWazuhAuthAndDedup(t *testing.T) {
	a := testApp(t)
	t.Setenv("INGEST_TOKEN", "secret")
	body := `{"id":"one","rule":{"id":"5710","level":10,"description":"Failed SSH"},"agent":{"name":"pve01"},"data":{"srcip":"198.51.100.8"},"full_log":"sshd failed"}`
	h := a.routes()
	send := func(secret string) *httptest.ResponseRecorder {
		r := testRequest("POST", "/api/wazuh", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if send("wrong").Code != 401 {
		t.Fatal("bad auth")
	}
	if send("secret").Code != 200 || send("secret").Code != 200 {
		t.Fatal("ingest failed")
	}
	if len(a.events) != 1 || a.events[0].Level != 10 || !a.events[0].Alert {
		t.Fatal("duplicate or lost metadata")
	}
}
func TestStorageFailureDoesNotBlock(t *testing.T) {
	a := testApp(t)
	a.state.Rules = []Rule{{"test", "test", "any", "failed", 1, 60, 10, true, true}}
	a.cfg.DataDir = filepath.Join(a.cfg.DataDir, "missing", "child")
	a.ingest(Device{"PVE", "192.168.1.10", "proxmox"}, "failed from 198.51.100.3")
	if len(a.state.Blocks) != 0 || len(a.events) != 0 || a.dropped != 1 {
		t.Fatal("blocked without durable event")
	}
}
func TestExpiredAndSimulatedNotPublished(t *testing.T) {
	a := testApp(t)
	t.Setenv("PFSENSE_FEED_TOKEN", "secret")
	a.cfg.AutoBlock = true
	a.state.Blocks["198.51.100.1"] = Block{"198.51.100.1", time.Now().Add(-time.Minute), "test", "published"}
	a.state.Blocks["198.51.100.2"] = Block{"198.51.100.2", time.Now().Add(time.Hour), "test", "simulation"}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, testRequest("GET", "/feeds/pfsense/secret", nil))
	if strings.Contains(w.Body.String(), "198.51.100.") {
		t.Fatal("expired or simulated leaked")
	}
}
func TestConfigPersistAndBoundedMemory(t *testing.T) {
	a := testApp(t)
	for i := 0; i < 2200; i++ {
		a.remember(Event{Time: time.Now()})
	}
	if len(a.events) != 2000 {
		t.Fatal("unbounded window")
	}
	b, e := os.ReadFile(a.configPath)
	if e != nil {
		t.Fatal(e)
	}
	var c Config
	if json.Unmarshal(b, &c) != nil || validateConfig(c) != nil {
		t.Fatal("invalid config")
	}
}
