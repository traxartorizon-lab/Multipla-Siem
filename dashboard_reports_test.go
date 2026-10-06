package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityReportOriginsIncludePIDPrefixedFirewallAndIPv6(t *testing.T) {
	cases := []struct{ kind, message, want string }{
		{"pfsense", "<130>Oct 5 filterlog[52588]: 5,,,1,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.12,192.168.1.2,111,22,0,S", "203.0.113.12"},
		{"pfsense", "filterlog[4]: 5,,,1,igb0,match,pass,in,6,0x0,0,64,tcp,6,60,2001:db8::3,2001:db8::4,123,22,0,S", "2001:db8::3"},
		{"proxmox", "pvedaemon authentication failure; rhost=2001:db8::5 user=root", "2001:db8::5"},
		{"proxmox", "kernel panic on host 192.0.2.50", ""},
	}
	for _, tc := range cases {
		e := Event{Kind: tc.kind, Message: tc.message, SenderIP: "100.83.245.103", Level: 12}
		if got := securitySourceIP(e); got != tc.want {
			t.Fatal(tc.kind, got, tc.want)
		}
	}
	a := testApp(t)
	now := time.Now().UTC()
	for i, tc := range cases {
		a.appendEvent(Event{ID: tc.want + tc.kind, Time: now, Device: "Security", Kind: tc.kind, Message: tc.message, Level: 12, Alert: i%2 == 0})
	}
	f := reportFilter{Kind: "infrastructure", Severity: "critical"}
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	report, err := a.buildReport(httptest.NewRequest("GET", "/", nil), f, day, day)
	if err != nil || report.Matched != 4 || report.CriticalWithoutIP != 1 || report.CriticalBySourceIP["203.0.113.12"] != 1 {
		t.Fatal("security aggregation failed", report, err)
	}
	f.SourceIP = "2001:db8::5"
	report, err = a.buildReport(httptest.NewRequest("GET", "/", nil), f, day, day)
	if err != nil || report.Matched != 1 {
		t.Fatal("origin filter failed", report, err)
	}
}

func TestViewerLayoutIsPersonalAndPersistsWithoutChangingOtherPreferences(t *testing.T) {
	a := testApp(t)
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	p := defaultPreferences()
	p.BackupDaily = true
	p.BackupDrive = true
	a.state.Preferences = map[string]Preferences{"admin@gmail.com": p, "other@example.com": defaultPreferences()}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/dashboard/layout", []byte(`{"order":["activity","devices"]}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	loaded, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	saved := loaded.preferences("admin@gmail.com")
	if len(saved.DashboardOrder) != 2 || saved.DashboardOrder[0] != "activity" || !saved.BackupDaily || !saved.BackupDrive || len(loaded.preferences("other@example.com").DashboardOrder) != 0 {
		t.Fatal("preferences changed outside own layout", saved)
	}
	for _, body := range []string{`{"order":["activity","activity"]}`, `{"order":["../../state.json"]}`} {
		w = httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/dashboard/layout", []byte(body)))
		if w.Code != 400 {
			t.Fatal("invalid layout accepted", w.Code)
		}
	}
	request := featureRequest(a, "admin@gmail.com", "PUT", "/api/dashboard/layout", []byte(`{"order":[]}`))
	request.Header.Del("X-CSRF-Token")
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, request)
	if w.Code != 403 {
		t.Fatal("layout CSRF bypass")
	}
}

func TestReportsReadStoredLogsOutsideDashboardAndFilterCriticalDevice(t *testing.T) {
	a := testApp(t)
	day := time.Now().UTC().AddDate(0, 0, -1)
	for _, e := range []Event{{ID: "old-critical", Time: day, Device: "Firewall A", Kind: "pfsense", Level: 12, Alert: true, Message: "kernel panic"}, {ID: "old-normal", Time: day, Device: "Firewall A", Kind: "pfsense", Message: "routine"}, {ID: "other-critical", Time: day, Device: "Firewall B", Kind: "pfsense", Level: 12, Alert: true, Message: "failure"}} {
		if !a.appendEvent(e) {
			t.Fatal("journal failed")
		}
	}
	a.events = nil
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	path := "/api/reports?start=" + day.Format("2006-01-02") + "&end=" + day.Format("2006-01-02") + "&device=Firewall%20A&severity=critical&type=alerts"
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", path, nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var report eventReport
	if json.Unmarshal(w.Body.Bytes(), &report) != nil || report.Matched != 1 || report.Alerts != 1 || report.Critical != 1 || report.Events[0].ID != "old-critical" {
		t.Fatal("historical filter mismatch", w.Body.String())
	}
	for _, suffix := range []string{strings.Replace(path, "severity=critical", "severity=invalid", 1), strings.Replace(path, "type=alerts", "type=unknown", 1), path + "&format=html"} {
		w = httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", suffix, nil))
		if w.Code != 400 {
			t.Fatal("invalid report query accepted", suffix, w.Code)
		}
	}
	// Cells derived from untrusted logs cannot become Excel formulas.
	for _, s := range []string{"=1+1", " +cmd", "@SUM(1)", "\tformula"} {
		if !strings.HasPrefix(csvSafe(s), "'") {
			t.Fatal("unsafe CSV", s)
		}
	}
}
