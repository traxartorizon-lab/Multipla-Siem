package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func n8nFixture(t *testing.T) N8NSettings {
	t.Helper()
	protocolKey(t)
	c, e := sealDriveToken("n8n", DriveToken{Access: strings.Repeat("secret-", 8)})
	if e != nil {
		t.Fatal(e)
	}
	return N8NSettings{Mode: "cloud", URL: "https://example.com/webhook/multipla", MinLevel: 12, Credentials: c, Revision: "revision", Verified: "revision", Enabled: true}
}

func TestN8NDestinationScope(t *testing.T) {
	s := N8NSettings{Mode: "self_hosted", URL: "https://100.79.144.108/webhook/siem", AllowedIP: "100.79.144.108", MinLevel: 12}
	if e := validateN8N(s); e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "100.100.100.100", "100.100.100.200", "0.0.0.0", "224.0.0.1", "192.0.2.1", "100.79.144.109"} {
		if n8nIPAllowed(netip.MustParseAddr(ip), s.AllowedIP) {
			t.Fatal("SSRF scope allowed", ip)
		}
	}
	for _, target := range []string{"http://example.com/webhook/a", "https://user:pass@example.com/webhook/a", "https://example.com/webhook-test/a", "https://example.com/webhook/", "https://example.com/webhook/a?secret=x", "https://example.com:99999/webhook/a", "https://127.0.0.1/webhook/a", "https://100.79.144.109/webhook/a"} {
		bad := s
		bad.URL = target
		if validateN8N(bad) == nil {
			t.Fatal("invalid URL accepted", target)
		}
	}
	s.Mode = "cloud"
	if validateN8N(s) == nil {
		t.Fatal("cloud private destination accepted")
	}
	if webhookClient("").CheckRedirect(nil, nil) == nil || n8nClient("").Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("transport safety lost")
	}
}

func TestN8NAuthenticatedContractAndAcknowledgement(t *testing.T) {
	s := n8nFixture(t)
	p := N8NPayload{Schema: 1, Product: "Multipla Siem", Version: productVersion(), Kind: "test", ID: token(), Time: time.Now().UTC(), Level: 1, Title: "Test"}
	for _, ack := range []string{"", `{"ok":true,"schema":1,"id":"wrong","kind":"test"}`, `{"ok":true,"schema":1,"id":"` + p.ID + `","kind":"alert"}`, `{"ok":true,"schema":1,"id":"` + p.ID + `","kind":"test"}`} {
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("X-Multipla-Token") != strings.Repeat("secret-", 8) || r.Header.Get("X-Multipla-Event-ID") != p.ID || r.Header.Get("X-Multipla-Timestamp") == "" {
				t.Fatal("authentication or identity missing")
			}
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "secret-") {
				t.Fatal("credential in payload")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(ack))}, nil
		})}
		e := deliverN8N(context.Background(), s, p, client)
		valid := strings.Contains(ack, `"kind":"test"`) && strings.Contains(ack, p.ID)
		if (e == nil) != valid {
			t.Fatal("ack validation", ack, e)
		}
	}
}

func TestN8NQueueSurvivesRestartRetriesAndAvoidsLoops(t *testing.T) {
	s := n8nFixture(t)
	a := testApp(t)
	a.state.N8N = s
	e := Event{ID: token(), Time: time.Now().UTC(), Level: 12, Alert: true, Rule: "Critical", Message: "RAW PRIVATE LOG", Device: "Firewall", Protocol: "syslog"}
	a.queueN8N(e)
	if len(a.state.N8NOutbox) != 1 {
		t.Fatal("alert missing")
	}
	stateBytes, _ := os.ReadFile(filepath.Join(a.cfg.DataDir, "state.json"))
	if strings.Contains(string(stateBytes), "RAW PRIVATE LOG") || strings.Contains(string(stateBytes), "secret-") {
		t.Fatal("queue leaked log or token")
	}
	restarted, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(restarted.state.N8NOutbox) != 1 {
		t.Fatal("queue lost on restart")
	}
	e.Protocol = "webhook"
	a.queueN8N(e)
	e.Protocol = "syslog"
	e.Level = 11
	a.queueN8N(e)
	if len(a.state.N8NOutbox) != 1 {
		t.Fatal("loop/threshold")
	}
	now := time.Now().UTC().Add(time.Second)
	calls := 0
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		code := 503
		body := ""
		if calls == 2 {
			code = 200
			body = `{"ok":true,"schema":1,"id":"` + e.ID + `","kind":"alert"}`
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	restarted.processN8N(now, client)
	if len(restarted.state.N8NOutbox) != 1 || restarted.state.N8NOutbox[0].Attempts != 1 || !restarted.state.N8NOutbox[0].Next.After(now) {
		t.Fatal("retry not durable")
	}
	restarted.processN8N(now.Add(time.Second), client)
	if calls != 1 {
		t.Fatal("backoff ignored")
	}
	restarted.processN8N(now.Add(time.Minute), client)
	if calls != 2 || len(restarted.state.N8NOutbox) != 0 || restarted.state.N8N.Delivered != 1 {
		t.Fatal("delivery acknowledgement")
	}
}

func TestN8NEndpointsAdminCSRFAndSecretIsolation(t *testing.T) {
	s := n8nFixture(t)
	a := testApp(t)
	a.state.N8N = s
	a.sessions["admin"] = Session{Email: "admin@gmail.com", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	for _, path := range []string{"/api/integrations/n8n", "/api/integrations/n8n/workflow"} {
		r := httptest.NewRequest("GET", a.origin+path, nil)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("unauthenticated access")
		}
		r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "admin"})
		w = httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), s.Credentials) || strings.Contains(w.Body.String(), "secret-") {
			t.Fatal("admin response leaked secret", w.Code)
		}
	}
	r := httptest.NewRequest("POST", a.origin+"/api/integrations/n8n/test", strings.NewReader(`{}`))
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "admin"})
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	a.state.Accounts = map[string]AccessAccount{"viewer@example.com": {Role: "viewer"}}
	a.cfg.AllowedEmails = append(a.cfg.AllowedEmails, "viewer@example.com")
	a.sessions["viewer"] = Session{Email: "viewer@example.com", Expires: time.Now().Add(time.Hour)}
	r = httptest.NewRequest("GET", a.origin+"/api/integrations/n8n", nil)
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "viewer"})
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("viewer integration access")
	}
}

func TestN8NEnablingRequiresTestAndRotationInvalidatesIt(t *testing.T) {
	s := n8nFixture(t)
	a := testApp(t)
	a.state.N8N = s
	a.sessions["admin"] = Session{Email: "admin@gmail.com", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	input := map[string]any{"mode": "cloud", "url": s.URL, "min_level": 12, "enabled": true, "token": strings.Repeat("new-secret-", 5)}
	data, _ := json.Marshal(input)
	r := httptest.NewRequest("PUT", a.origin+"/api/integrations/n8n", strings.NewReader(string(data)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", a.origin)
	r.Header.Set("X-CSRF-Token", "csrf")
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "admin"})
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 400 || a.state.N8N.Credentials != s.Credentials {
		t.Fatal("rotation enabled without test", w.Code)
	}
}

func TestN8NSaveAndEnableVerifiedConfiguration(t *testing.T) {
	s := n8nFixture(t)
	a := testApp(t)
	a.state.N8N = s
	a.sessions["admin"] = Session{Email: "admin@gmail.com", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	for _, enabled := range []bool{false, true} {
		body, _ := json.Marshal(map[string]any{"mode": s.Mode, "url": s.URL, "min_level": 12, "enabled": enabled})
		r := httptest.NewRequest("PUT", a.origin+"/api/integrations/n8n", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.origin)
		r.Header.Set("X-CSRF-Token", "csrf")
		r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "admin"})
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 200 || a.state.N8N.Enabled != enabled || a.state.N8N.Credentials != s.Credentials {
			t.Fatal("save/enable", w.Code, w.Body.String())
		}
	}
}

func TestN8NWorkflowExportHasNoCredentialsAndTestBranchTerminates(t *testing.T) {
	w := n8nWorkflow()
	data, e := json.Marshal(w)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(data), `"credentials"`) || w["active"] != false {
		t.Fatal("workflow credentials/activation")
	}
	connections := w["connections"].(map[string]any)
	if _, exists := connections["Confirmar teste sem automações"]; exists {
		t.Fatal("test triggers actions")
	}
	for _, n := range w["nodes"].([]any) {
		node := n.(map[string]any)
		if node["type"] == "n8n-nodes-base.webhook" && node["parameters"].(map[string]any)["authentication"] != "headerAuth" {
			t.Fatal("unauthenticated webhook")
		}
	}
}

func TestN8NPermanentFailureAndQueueLimits(t *testing.T) {
	s := n8nFixture(t)
	a := testApp(t)
	a.state.N8N = s
	e := Event{ID: token(), Time: time.Now().UTC(), Level: 12, Alert: true, Rule: "Critical\n" + strings.Repeat("x", 2000), Protocol: "syslog"}
	a.queueN8N(e)
	if strings.Contains(a.state.N8NOutbox[0].Payload.Title, "\n") || len(a.state.N8NOutbox[0].Payload.Title) > 1024 {
		t.Fatal("unbounded/control characters in summary")
	}
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("sensitive server response"))}, nil
	})}
	a.processN8N(time.Now().Add(time.Second), client)
	if len(a.state.N8NOutbox) != 0 || a.state.N8N.Failed != 1 || strings.Contains(a.state.N8N.Status, "sensitive") {
		t.Fatal("permanent error handling")
	}
	a.state.N8NOutbox = make([]N8NDelivery, n8nQueueLimit)
	a.queueN8N(e)
	if len(a.state.N8NOutbox) != n8nQueueLimit || a.state.N8N.Failed != 2 {
		t.Fatal("queue bound")
	}
}

func TestN8NConfigurationBackupOmitsIntegrationSecrets(t *testing.T) {
	s := n8nFixture(t)
	a := testApp(t)
	a.state.N8N = s
	a.queueN8N(Event{ID: token(), Time: time.Now().UTC(), Level: 12, Alert: true, Protocol: "syslog", Rule: "Critical"})
	b := a.backupDocument("admin@gmail.com")
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), s.URL) || strings.Contains(string(raw), s.Credentials) || strings.Contains(string(raw), "n8n_outbox") {
		t.Fatal("integration exported")
	}
	if err := a.restoreBackup("admin@gmail.com", raw); err != nil {
		t.Fatal(err)
	}
	if a.state.N8N.Enabled || a.state.N8N.Verified != "" || len(a.state.N8NOutbox) != 0 {
		t.Fatal("restore did not pause integration")
	}
}
