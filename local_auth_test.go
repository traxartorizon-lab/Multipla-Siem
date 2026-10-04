package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalEnrollmentPersistentLoginAndIsolation(t *testing.T) {
	a := testApp(t)
	a.sessions["enrollment"] = Session{Email: "bootstrap", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	req := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/account/local", strings.NewReader(`{"email":"new-admin@example.com","password":"A-long-local-password-2026!"}`))
	req.Header.Set("Origin", a.origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "csrf")
	req.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "enrollment"})
	response := httptest.NewRecorder()
	a.routes().ServeHTTP(response, req)
	if response.Code != 200 {
		t.Fatalf("enrollment failed: %d %s", response.Code, response.Body.String())
	}
	if _, ok := a.sessions["enrollment"]; ok {
		t.Fatal("bootstrap session survived")
	}
	disk, _ := os.ReadFile(filepath.Join(a.cfg.DataDir, "state.json"))
	if strings.Contains(string(disk), "A-long-local-password-2026!") {
		t.Fatal("plaintext password persisted")
	}
	exported, _ := json.Marshal(a.backupDocument("new-admin@example.com"))
	if strings.Contains(string(exported), a.state.LocalAdmin.Hash) {
		t.Fatal("password hash exported")
	}
	restarted, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"wrong-password", "A-long-local-password-2026!"} {
		form := url.Values{"email": {"new-admin@example.com"}, "password": {password}}
		req = httptest.NewRequest("POST", a.origin+"/auth/password", strings.NewReader(form.Encode()))
		req.Header.Set("Origin", a.origin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response = httptest.NewRecorder()
		restarted.routes().ServeHTTP(response, req)
		expected := 403
		if password != "wrong-password" {
			expected = 303
		}
		if response.Code != expected {
			t.Fatalf("login: %d", response.Code)
		}
	}
}

func TestLocalEnrollmentRequiresSessionAndCSRF(t *testing.T) {
	a := testApp(t)
	req := httptest.NewRequest("POST", a.origin+"/api/account/local", strings.NewReader(`{"email":"admin@gmail.com","password":"long-enough-password"}`))
	req.Header.Set("Origin", a.origin)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	a.routes().ServeHTTP(response, req)
	if response.Code != 401 {
		t.Fatal(response.Code)
	}
	a.sessions["enrollment"] = Session{Email: "bootstrap", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	req.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "enrollment"})
	response = httptest.NewRecorder()
	a.routes().ServeHTTP(response, req)
	if response.Code != 403 {
		t.Fatal(response.Code)
	}
}

func TestGoogleSettingsEncryptedAndExcludedFromBackup(t *testing.T) {
	a := testApp(t)
	t.Setenv("BACKUP_ENCRYPTION_KEY", hex.EncodeToString([]byte(token())[:32]))
	a.sessions["admin"] = Session{Email: "admin@gmail.com", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	req := httptest.NewRequest("POST", a.origin+"/api/settings/google", strings.NewReader(`{"client_id":"fixture.apps.googleusercontent.com","client_secret":"private-client-secret-2026"}`))
	req.Header.Set("Origin", a.origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "csrf")
	req.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "admin"})
	response := httptest.NewRecorder()
	a.routes().ServeHTTP(response, req)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	if a.googleSecret("GOOGLE_CLIENT_SECRET") != "private-client-secret-2026" {
		t.Fatal("credential unavailable")
	}
	disk, _ := os.ReadFile(filepath.Join(a.cfg.DataDir, "state.json"))
	if strings.Contains(string(disk), "private-client-secret-2026") {
		t.Fatal("plaintext persisted")
	}
	backup, _ := json.Marshal(a.backupDocument("admin@gmail.com"))
	if strings.Contains(string(backup), a.state.GoogleSettings) {
		t.Fatal("OAuth config exported")
	}
	if redact("private-client-secret-2026") != "[REDACTED]" {
		t.Fatal("credential not redacted")
	}
	googleRedaction.Store(nil)
}
