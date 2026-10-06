package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestViewerCannotChangeOrReadBackups(t *testing.T) {
	a := testApp(t)
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{"GET", "/api/snapshot", 200}, {"GET", "/api/backups", 403}, {"GET", "/api/accounts", 403}, {"GET", "/api/receivers", 403},
		{"PUT", "/api/config", 403}, {"POST", "/api/rules/test", 403}, {"POST", "/api/drive/connect", 403}, {"PUT", "/api/accounts", 403},
		{"POST", "/api/activity", 200}, {"POST", "/auth/logout", 200},
	} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", tc.method, tc.path, []byte(`{}`)))
		if w.Code != tc.code {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}

func TestAccountsScriptIsServed(t *testing.T) {
	a := testApp(t)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, httptest.NewRequest("GET", "/accounts.js", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "javascript") || !strings.Contains(w.Body.String(), "renderAccounts") {
		t.Fatal("account UI unavailable", w.Code)
	}
}

func TestAccountsCreateEditRevokeAndPersist(t *testing.T) {
	a := testApp(t)
	body := []byte(`{"email":"viewer@example.com","role":"viewer","password":"long-unique-password-123","disabled":false}`)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/accounts", body))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if a.state.Accounts["viewer@example.com"].Hash == "" {
		t.Fatal("missing password hash")
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/accounts", nil))
	if strings.Contains(w.Body.String(), "password_hash") || strings.Contains(w.Body.String(), "long-unique") {
		t.Fatal("account credentials leaked")
	}
	var result map[string]any
	if json.Unmarshal(w.Body.Bytes(), &result) != nil {
		t.Fatal("invalid response")
	}
	reloaded, err := newApp(a.cfg, a.configPath, false)
	if err != nil || reloaded.state.Accounts["viewer@example.com"].Role != "viewer" {
		t.Fatal("role not persisted", err)
	}
	body = []byte(`{"email":"viewer@example.com","role":"viewer","password":"","disabled":true}`)
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/accounts", body))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "viewer@example.com", "GET", "/api/snapshot", nil))
	if w.Code != 401 {
		t.Fatal("disabled account retained access", w.Code)
	}
}
