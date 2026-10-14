package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuditUnauthenticatedNewSensitiveRoutes(t *testing.T) {
	for _, path := range []string{"/api/critical-sounds", "/api/ssh/sessions", "/api/ssh/identity", "/api/system/reboot", "/api/assistant/plan", "/api/receivers", "/api/accounts", "/api/backups", "/api/drive/connect", "/api/n8n"} {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			a := testApp(t)
			r := testRequest(method, path, strings.NewReader(`{}`))
			r.Header.Set("Origin", a.origin)
			r.Header.Set("Authorization", "Bearer forged")
			r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "forged"})
			w := httptest.NewRecorder()
			a.routes().ServeHTTP(w, r)
			if w.Code >= 200 && w.Code < 300 {
				t.Fatalf("unauthenticated %s %s accepted", method, path)
			}
		}
	}
}
func TestAuditViewerCannotUseAdministrativeCapabilities(t *testing.T) {
	for _, path := range []string{"/api/ssh/identity", "/api/ssh/trust", "/api/ssh/sessions", "/api/system/reboot", "/api/devices/metrics-key", "/api/receivers/snmp", "/api/critical-sounds/forged"} {
		a := testApp(t)
		a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", path, []byte(`{"confirm":"REINICIAR"}`)))
		if w.Code >= 200 && w.Code < 300 {
			t.Fatal("viewer accepted", path)
		}
	}
}
func TestAuditCSRFAndTerminalCrossAccount(t *testing.T) {
	a := testApp(t)
	for _, origin := range []string{"", "null", "https://evil.example"} {
		r := featureRequest(a, "admin@gmail.com", "PUT", "/api/critical-sounds/forged", []byte(`{"sound":true}`))
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("CSRF", origin, w.Code)
		}
	}
	a.sshTerminals = map[string]*sshTerminal{"known-id": {owner: "another@example.com", status: "connected", lastRead: time.Now()}}
	r := featureRequest(a, "admin@gmail.com", "GET", "/api/ssh/sessions/known-id", nil)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("terminal IDOR", w.Code)
	}
}
func TestAuditAgentKeyDoesNotBecomeWebSession(t *testing.T) {
	a := testApp(t)
	a.nativeTLS = true
	r := testRequest("GET", "/api/snapshot", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 43))
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}
