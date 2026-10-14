package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDesktopGrantIsRestrictedRevocableAndBoundToAccount(t *testing.T) {
	a := testApp(t)
	request := featureRequest(a, "admin@gmail.com", "POST", "/api/desktop/grants", []byte(`{"name":"PC teste"}`))
	request.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, request)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var created struct{ ID, Key string }
	if json.Unmarshal(w.Body.Bytes(), &created) != nil || len(created.Key) != 43 {
		t.Fatal("invalid grant")
	}
	for _, g := range a.state.DesktopGrants {
		if g.Digest == created.Key {
			t.Fatal("plaintext token persisted")
		}
	}
	a.state.Notifications = []SystemNotification{{ID: "alert-1", Time: time.Now(), Title: "Test", Severity: "critical"}}
	call := func(method, path, authorization string, tlsEnabled bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if tlsEnabled {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/desktop/notifications", "Bearer "+created.Key, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/snapshot", "/api/accounts", "/api/system/update"} {
		if w := call("GET", path, "Bearer "+created.Key, true); w.Code != 401 {
			t.Fatal("grant became web session", path, w.Code)
		}
	}
	if w := call("GET", "/api/desktop/notifications", created.Key, true); w.Code != 401 {
		t.Fatal("raw secret accepted")
	}
	if w := call("GET", "/api/desktop/notifications", "Bearer "+created.Key, false); w.Code != 401 {
		t.Fatal("HTTP accepted")
	}
	if w := call("POST", "/api/desktop/notifications/alert-1/read", "Bearer "+created.Key, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !a.state.NotificationReads["admin@gmail.com"]["alert-1"] {
		t.Fatal("read not persisted")
	}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Group: groupAlerts, Role: "viewer"}}
	if w := call("GET", "/api/desktop/notifications", "Bearer "+created.Key, true); w.Code != 401 {
		t.Fatal("changed group retained old grant")
	}
}

func TestDesktopGrantOtherOwnerCannotRevoke(t *testing.T) {
	a := testApp(t)
	a.state.DesktopGrants = map[string]DesktopGrant{"other": {ID: "other", Owner: "other@example.com", Expires: time.Now().Add(time.Hour)}}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "DELETE", "/api/desktop/grants/other", nil))
	if w.Code != 404 || len(a.state.DesktopGrants) != 1 {
		t.Fatal("cross-owner revocation", w.Code)
	}
}

func TestUpdatePrivilegeBridgeIsFixedAndNarrow(t *testing.T) {
	if !strings.Contains(appUpdatePolicy, `action.lookup("unit") === "multipla-app-update.service"`) || !strings.Contains(appUpdatePolicy, `action.lookup("verb") === "start"`) {
		t.Fatal("overbroad policy")
	}
	if !strings.Contains(appUpdateUnit, "ExecStart=/usr/local/bin/multipla-update\n") || strings.Contains(appUpdateUnit, "bash") || strings.Contains(appUpdateUnit, "sudo") {
		t.Fatal("arbitrary command bridge")
	}
	a := testApp(t)
	r := featureRequest(a, "admin@gmail.com", "POST", "/api/system/update", []byte(`{"confirm":"ATUALIZAR","password":"wrong-credential-123"}`))
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("HTTP update accepted", w.Code)
	}
}
