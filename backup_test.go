package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func featureRequest(a *App, email, method, path string, body []byte) *http.Request {
	a.sessions["feature-session"] = Session{"", email, "csrf", time.Now().Add(time.Hour)}
	a.active["feature-session"] = time.Now()
	r := testRequest(method, path, bytes.NewReader(body))
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "feature-session"})
	r.Header.Set("Origin", a.origin)
	r.Header.Set("X-CSRF-Token", "csrf")
	return r
}
func TestBackupExportExcludesSecretsAndHostPaths(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "subject1"
	t.Setenv("GOOGLE_CLIENT_SECRET", "private-google-secret")
	a.state.DriveTokens["admin@gmail.com"] = "encrypted-fixture"
	b := a.backupDocument("admin@gmail.com")
	data, _ := json.Marshal(b)
	for _, value := range []string{"private-google-secret", "encrypted-fixture", "data_dir", "tls_key", "bootstrap_digest", "drive_tokens", "listen", "sessions"} {
		if strings.Contains(string(data), value) {
			t.Fatal("export leaked " + value)
		}
	}
	if _, e := decodeBackup(data); e != nil {
		t.Fatal(e)
	}
}
func TestBackupRestorePreservesHostAndPausesActions(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "subject1"
	a.cfg.AutoBlock = true
	a.cfg.TLSKey = "private-key-path"
	a.state.DriveTokens["admin@gmail.com"] = "ciphertext"
	b := a.backupDocument("admin@gmail.com")
	b.Config.RetentionDays = 30
	b.Preferences.BackupDaily = true
	b.Preferences.BackupDrive = true
	b.Preferences.DefaultPage = "events"
	data, _ := json.Marshal(b)
	if e := a.restoreBackup("admin@gmail.com", data); e != nil {
		t.Fatal(e)
	}
	if a.cfg.AutoBlock || a.cfg.TLSKey != "private-key-path" || a.cfg.RetentionDays != 30 || a.state.DriveTokens["admin@gmail.com"] != "ciphertext" {
		t.Fatal("unsafe restore")
	}
	p := a.preferences("admin@gmail.com")
	if p.BackupDaily || p.BackupDrive || p.DefaultPage != "events" {
		t.Fatal("preferences restoration")
	}
}
func TestBackupRejectsMalformedInjectionAndLockout(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "subject1"
	b := a.backupDocument("admin@gmail.com")
	data, _ := json.Marshal(b)
	cases := [][]byte{append(append([]byte{}, data...), []byte(`{}`)...), []byte(strings.Replace(string(data), `"config":{`, `"config":{"data_dir":"/etc",`, 1)), bytes.Repeat([]byte("x"), backupLimit+1)}
	b.Config.AllowedEmails = []string{"other@gmail.com"}
	deny, _ := json.Marshal(b)
	cases = append(cases, deny)
	for _, v := range cases {
		if e := a.restoreBackup("admin@gmail.com", v); e == nil {
			t.Fatal("unsafe backup accepted")
		}
	}
	if a.cfg.RetentionDays != 7 {
		t.Fatal("failed restore modified config")
	}
}
func TestBackupLocalRetentionAccountIsolationAndTraversal(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "subject1"
	for i := 0; i < 13; i++ {
		if _, e := a.createLocalBackup("admin@gmail.com"); e != nil {
			t.Fatal(e)
		}
	}
	list, e := a.backupList("admin@gmail.com")
	if e != nil || len(list) != 10 {
		t.Fatalf("retention %d %v", len(list), e)
	}
	if _, e = a.readLocalBackup("other@gmail.com", list[0].ID); e == nil {
		t.Fatal("cross-account access")
	}
	if _, e = a.readLocalBackup("admin@gmail.com", "../../secrets.env"); e == nil {
		t.Fatal("traversal")
	}
	data, e := a.readLocalBackup("admin@gmail.com", list[0].ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = decodeBackup(data); e != nil {
		t.Fatal(e)
	}
}
func TestPreferencesAccountPersistence(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "subject1"
	p := defaultPreferences()
	p.RefreshSeconds = 15
	p.DefaultPage = "events"
	data, _ := json.Marshal(p)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/preferences", data))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	other := a.preferences("other@gmail.com")
	if other.DefaultPage != "overview" {
		t.Fatal("cross-account preferences")
	}
	again, e := newApp(a.cfg, a.configPath, false)
	if e != nil || again.preferences("admin@gmail.com").RefreshSeconds != 15 {
		t.Fatal("preferences lost")
	}
}
func TestBackupSchedulingTimezoneAndRestartDedup(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "subject1"
	p := defaultPreferences()
	p.BackupDaily = true
	a.state.Preferences["admin@gmail.com"] = p
	a.runScheduledBackups(time.Date(2026, 10, 4, 3, 0, 0, 0, time.UTC))
	v, _ := a.backupList("admin@gmail.com")
	if len(v) != 0 {
		t.Fatal("wrong timezone")
	}
	now := time.Date(2026, 10, 4, 5, 0, 0, 0, time.UTC)
	a.runScheduledBackups(now)
	a.runScheduledBackups(now.Add(time.Minute))
	v, _ = a.backupList("admin@gmail.com")
	if len(v) != 1 {
		t.Fatal("duplicate or missed schedule")
	}
	again, e := newApp(a.cfg, a.configPath, false)
	if e != nil {
		t.Fatal(e)
	}
	again.runScheduledBackups(now.Add(time.Hour))
	v, _ = again.backupList("admin@gmail.com")
	if len(v) != 1 {
		t.Fatal("restart repeated schedule")
	}
}
func TestBackupNewRoutesRequireAuthAndCSRF(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "subject1"
	paths := []string{"/api/preferences", "/api/backups", "/api/backup/export", "/api/drive/backups"}
	for _, p := range paths {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, testRequest("GET", p, nil))
		if w.Code != 401 {
			t.Fatal("public " + p)
		}
	}
	r := featureRequest(a, "admin@gmail.com", "POST", "/api/backup/import", []byte(`{}`))
	r.Header.Del("X-CSRF-Token")
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("restore CSRF accepted")
	}
}
func TestBackupRestoreDiskFailureLeavesOriginal(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "subject1"
	b := a.backupDocument("admin@gmail.com")
	b.Config.RetentionDays = 30
	data, _ := json.Marshal(b)
	a.configPath = filepath.Join(a.cfg.DataDir, "absent", "config.json")
	if e := a.restoreBackup("admin@gmail.com", data); e == nil || a.cfg.RetentionDays != 7 {
		t.Fatal("partial restore")
	}
}
func TestDriveTokenEncryptionIdentityAndTampering(t *testing.T) {
	t.Setenv("BACKUP_ENCRYPTION_KEY", fmt.Sprintf("%x", sha256.Sum256([]byte(token()))))
	fixture := DriveToken{Subject: "subject1", Access: "access-secret", Refresh: "refresh-secret", Expires: time.Now().Add(time.Hour)}
	encrypted, e := sealDriveToken("admin@gmail.com", fixture)
	if e != nil || strings.Contains(encrypted, "refresh-secret") {
		t.Fatal("token encryption")
	}
	decoded, e := openDriveToken("admin@gmail.com", encrypted)
	if e != nil || decoded.Refresh != fixture.Refresh {
		t.Fatal("roundtrip")
	}
	if _, e = openDriveToken("other@gmail.com", encrypted); e == nil {
		t.Fatal("other identity decrypted")
	}
	if _, e = openDriveToken("admin@gmail.com", encrypted[:len(encrypted)-3]+"abc"); e == nil {
		t.Fatal("tampering accepted")
	}
}
func TestDriveUploadUsesMinimalPrivateMetadata(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "subject1"
	t.Setenv("BACKUP_ENCRYPTION_KEY", fmt.Sprintf("%x", sha256.Sum256([]byte(token()))))
	if e := a.storeDriveToken("admin@gmail.com", DriveToken{Subject: "subject1", Access: "access-fixture", Refresh: "refresh-fixture", Expires: time.Now().Add(time.Hour)}); e != nil {
		t.Fatal(e)
	}
	old := client
	defer func() { client = old }()
	client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "www.googleapis.com" || !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/related") {
			t.Fatal("upload target")
		}
		data, _ := io.ReadAll(r.Body)
		if !bytes.Contains(data, []byte(`"owner":"`+driveOwner("admin@gmail.com")+`"`)) || bytes.Contains(data, []byte("refresh-fixture")) {
			t.Fatal("upload metadata or secret")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"fake-file-id"}`)), Header: http.Header{}}, nil
	})}
	if e := a.uploadDriveBackup("admin@gmail.com", []byte(`{"product":"Multipla Siem"}`)); e != nil {
		t.Fatal(e)
	}
	disk, _ := os.ReadFile(filepath.Join(a.cfg.DataDir, "state.json"))
	if bytes.Contains(disk, []byte("refresh-fixture")) {
		t.Fatal("plaintext token persisted")
	}
}
func TestDriveRestoreRejectsForeignMetadata(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "subject1"
	t.Setenv("BACKUP_ENCRYPTION_KEY", fmt.Sprintf("%x", sha256.Sum256([]byte(token()))))
	a.storeDriveToken("admin@gmail.com", DriveToken{Subject: "subject1", Access: "access", Refresh: "refresh", Expires: time.Now().Add(time.Hour)})
	old := client
	defer func() { client = old }()
	calls := 0
	client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"file","mimeType":"application/json","appProperties":{"product":"multipla-siem","schema":"1","owner":"foreign"}}`)), Header: http.Header{}}, nil
	})}
	if e := a.restoreDriveBackup("admin@gmail.com", "file"); e == nil || calls != 1 {
		t.Fatal("foreign backup downloaded")
	}
	if e := a.restoreDriveBackup("admin@gmail.com", "../../token"); e == nil {
		t.Fatal("unsafe file ID")
	}
}
func TestDriveChangedGoogleIdentityRejectsCredential(t *testing.T) {
	a := testApp(t)
	a.state.GoogleSubjects["admin@gmail.com"] = "new-subject"
	t.Setenv("BACKUP_ENCRYPTION_KEY", fmt.Sprintf("%x", sha256.Sum256([]byte(token()))))
	if err := a.storeDriveToken("admin@gmail.com", DriveToken{Subject: "old-subject", Access: "secret", Refresh: "secret", Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	old := client
	defer func() { client = old }()
	client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		t.Fatal("changed identity reached Google")
		return nil, nil
	})}
	if _, err := a.driveAccess("admin@gmail.com"); err == nil {
		t.Fatal("changed identity accepted")
	}
}
