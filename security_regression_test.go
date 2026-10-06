package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecurityBootstrapCannotReplayAfterRestart(t *testing.T) {
	a := testApp(t)
	value := token()
	t.Setenv("BOOTSTRAP_TOKEN", value)
	login := func(a *App) int {
		r := testRequest("POST", "/auth/local", strings.NewReader("token="+value))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", a.origin)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		return w.Code
	}
	if login(a) != 303 {
		t.Fatal("initial login failed")
	}
	b, e := newApp(a.cfg, a.configPath, false)
	if e != nil {
		t.Fatal(e)
	}
	if login(b) != 403 {
		t.Fatal("consumed token replayed after restart")
	}
	raw, _ := os.ReadFile(filepath.Join(a.cfg.DataDir, "state.json"))
	if strings.Contains(string(raw), value) {
		t.Fatal("bootstrap token stored in state")
	}
}
func TestSecurityLegacyExportRedactsCredentials(t *testing.T) {
	a := testApp(t)
	value := token()
	t.Setenv("GMAIL_APP_PASSWORD", value)
	ev := Event{ID: "old", Time: time.Now(), Message: "password=legacy-secret " + value, Rule: "Rule " + value}
	b, _ := json.Marshal(ev)
	os.WriteFile(a.journalPath(time.Now()), append(b, '\n'), 0600)
	a.sessions["s"] = Session{"", "admin@gmail.com", "csrf", time.Now().Add(time.Hour)}
	r := testRequest("GET", "/api/export?day="+time.Now().UTC().Format("2006-01-02"), nil)
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "s"})
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "legacy-secret") || strings.Contains(w.Body.String(), value) {
		t.Fatal("legacy export leaked credentials")
	}
}
func TestSecurityLogQuotaFailClosed(t *testing.T) {
	a := testApp(t)
	a.cfg.MaxDailyMB = 1
	a.state.Rules = []Rule{{"test", "test", "any", "failed", 1, 60, 10, true, true}}
	os.WriteFile(a.journalPath(time.Now()), []byte(strings.Repeat("x", 1024*1024)), 0600)
	a.ingest(Device{Name: "PVE", IP: "192.168.1.2", Kind: "proxmox"}, "failed from 198.51.100.1")
	if a.dropped != 1 || len(a.events) != 0 || len(a.state.Blocks) != 0 || a.storageError == "" {
		t.Fatal("quota did not stop ingestion and response")
	}
}
func TestSecurityBootstrapRotationPreservesGoogle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.env")
	original := token()
	os.WriteFile(path, []byte("BOOTSTRAP_TOKEN="+original+"\nGOOGLE_CLIENT_SECRET=existing-google-secret\n"), 0600)
	if e := rotateBootstrapFile(path); e != nil {
		t.Fatal(e)
	}
	values, e := readCredentialValues(path)
	if e != nil || !validLocalToken(values["BOOTSTRAP_TOKEN"]) || values["BOOTSTRAP_TOKEN"] == original || values["GOOGLE_CLIENT_SECRET"] != "existing-google-secret" {
		t.Fatal("rotation lost credentials or did not create a strong token")
	}
}
func TestSecurityWeakAndRepeatedCredentialsRejected(t *testing.T) {
	for _, v := range []string{"short", strings.Repeat("a", 64), strings.Repeat("abcd", 16), "SUBSTITUA_PELO_TOKEN_" + strings.Repeat("0", 64)} {
		if validLocalToken(v) {
			t.Fatal("weak token accepted")
		}
	}
	if !validLocalToken(token()) {
		t.Fatal("generated credential rejected")
	}
}
