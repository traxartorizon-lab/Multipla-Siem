package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCriticalDescriptionLifecycleAndDashboard(t *testing.T) {
	a := testApp(t)
	now := time.Now().UTC()
	message := `<37>1 2026-10-09T10:20:19Z firewall sshguard 86224 - - Attack from "211.149.182.162" on service SSH with danger 2.`
	seed := Event{ID: "seed", Time: now.Add(-time.Hour), Message: message, Kind: "pfsense", Device: "Firewall"}
	a.appendEvent(seed)
	change := func(critical, sound bool) {
		t.Helper()
		body, _ := json.Marshal(map[string]bool{"critical": critical, "sound": sound})
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/events/seed/critical-pattern", body))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	change(true, true)
	projected := a.classifiedEvent(seed)
	if !projected.Alert || projected.Level != 15 || projected.SourceIP != "211.149.182.162" || !projected.Classification.Sound || len(a.criticalDashboardEvents()) != 1 {
		t.Fatal(projected)
	}
	future := seed
	future.ID = "future"
	future.Time = time.Now().Add(time.Second)
	future.Message = strings.ReplaceAll(strings.ReplaceAll(message, "211.149.182.162", "2001:db8::1"), "86224", "1234")
	e := a.classifiedEvent(future)
	if !e.Alert || e.SourceIP != "2001:db8::1" || e.Level != 15 {
		t.Fatal("future classification", e)
	}
	different := future
	different.Message = strings.ReplaceAll(future.Message, "service SSH", "service SMTP")
	if a.classifiedEvent(different).Level >= 12 {
		t.Fatal("description broadened")
	}
	change(true, false)
	if a.classifiedEvent(future).Classification.Sound {
		t.Fatal("sound toggle")
	}
	loaded, err := newApp(a.cfg, a.configPath, false)
	if err != nil || loaded.classifiedEvent(future).Level != 15 {
		t.Fatal("restart", err)
	}
	change(false, false)
	if a.classifiedEvent(future).Level >= 12 || a.classifiedEvent(seed).Level >= 12 || len(a.criticalDashboardEvents()) != 0 {
		t.Fatal("unmark did not apply")
	}
	if a.events[0].Level != 0 || a.events[0].SourceIP != "" {
		t.Fatal("original mutated")
	}
}
func TestCriticalHistoryAndIPExport(t *testing.T) {
	a := testApp(t)
	seed := Event{ID: "old", Time: time.Now().Add(-time.Hour), Device: "Firewall", Kind: "pfsense", Message: `sshguard: Attack from "203.0.113.42" on service SSH with danger 2.`}
	a.appendEvent(seed)
	a.events = nil
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/events/old/critical-pattern", []byte(`{"critical":true,"sound":false}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/events/critical-ips?download=1", nil))
	if w.Code != 200 || w.Body.String() != "203.0.113.42\n" || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/events/old/critical-pattern", []byte(`{"critical":false,"sound":false}`)))
	if w.Code != 403 {
		t.Fatal("viewer mutation")
	}
	rows := aggregateCriticalIPs([]Event{{ID: "a", Level: 15, SourceIP: "bad", SenderIP: "100.1.2.3"}, {ID: "b", Level: 15, SourceIP: "2001:db8::1"}, {ID: "b", Level: 15, SourceIP: "2001:db8::1"}})
	if len(rows) != 1 || rows[0].Count != 1 {
		t.Fatal(rows)
	}
}
func TestDashboardCardsSizesAndSelectionsPersist(t *testing.T) {
	a := testApp(t)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/dashboard/layout", []byte(`{"order":["resources","resources-2"],"cards":{"resources":{"width":1,"height":300,"device":"192.0.2.3"},"resources-2":{"width":4,"device":"192.0.2.2"}}}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	loaded, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	p := loaded.preferences("admin@gmail.com")
	if p.DashboardCards["resources"].Device == p.DashboardCards["resources-2"].Device || p.DashboardCards["resources"].Height != 300 {
		t.Fatal(p)
	}
	for _, body := range []string{`{"order":["resources-9"]}`, `{"order":[],"cards":{"resources":{"width":5}}}`, `{"order":[],"cards":{"resources":{"height":1}}}`, `{"order":[],"cards":{"unknown":{}}}`} {
		w = httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/dashboard/layout", []byte(body)))
		if w.Code != 400 {
			t.Fatal("bad layout accepted", body)
		}
	}
}
func TestResourcePingParserAndRetention(t *testing.T) {
	sample := parseResourcePing("3 packets transmitted, 2 received, 33% packet loss\nrtt min/avg/max/mdev = 1.000/2.000/3.000/0.500 ms", errors.New("exit 1"))
	if sample.Sent != 3 || sample.Received != 2 || sample.LatencyAvg == nil || *sample.LatencyAvg != 2 || *sample.LatencyMax != 3 {
		t.Fatal(sample)
	}
	offline := parseResourcePing("3 packets transmitted, 0 received, 100% packet loss", errors.New("exit 1"))
	if offline.Sent != 3 || offline.Received != 0 || offline.LatencyAvg != nil {
		t.Fatal(offline)
	}
	unavailable := parseResourcePing("permission denied", errors.New("permission"))
	if unavailable.Sent != 0 || unavailable.PingError == "" {
		t.Fatal(unavailable)
	}
	now := time.Now()
	samples := retainResourceSamples([]ResourceSample{{Time: now.Add(-25 * time.Hour)}, {Time: now.Add(-time.Minute)}, {Time: now.Add(time.Hour)}}, now)
	if len(samples) != 1 {
		t.Fatal(samples)
	}
	a := testApp(t)
	ip := a.cfg.Devices[0].IP
	os.MkdirAll(filepath.Dir(a.resourceHistoryPath(ip)), 0700)
	atomicJSON(a.resourceHistoryPath(ip), samples)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/devices/resource-history?ip="+ip, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "interval_seconds") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestSecurityOriginsIncludeUnclassifiedHistory(t *testing.T) {
	messages := []struct{ raw, ip string }{
		{`<37>1 2026-10-09T12:45:00Z firewall sshguard 1 - - Attack from "107.150.105.116" on service SSH with danger 10.`, "107.150.105.116"},
		{`sshguard[1]: Blocking "203.0.113.42/32" for 86400 secs`, "203.0.113.42"},
		{`sshd-session: Invalid user halley from 2001:db8::42 port 47046`, "2001:db8::42"},
		{`sshguard[1]: Blocking "2001:db8::42/128" for 86400 secs`, "2001:db8::42"},
		{`application: Blocking "203.0.113.42" for 86400 secs`, ""},
		{`sshguard[1]: Blocking "192.0.2.0/24" for 86400 secs`, ""},
	}
	a := testApp(t)
	for i, m := range messages {
		if got := securityLogSourceIP(m.raw); got != m.ip {
			t.Fatalf("%s: got %s want %s", m.raw, got, m.ip)
		}
		if m.ip != "" {
			a.appendEvent(Event{ID: fmt.Sprintf("security-%d", i), Time: time.Now().Add(-time.Minute), Kind: "generic", Device: "Firewall", Message: m.raw})
		}
	}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/events/critical-ips?download=1", nil))
	if w.Code != 200 || w.Body.String() != "107.150.105.116\n2001:db8::42\n203.0.113.42\n" {
		t.Fatalf("history export: %d %s", w.Code, w.Body.String())
	}
	rows := aggregateCriticalIPs([]Event{{ID: "original", SourceIP: "203.0.113.1"}, {ID: "alert", ParentID: "original", Level: 12, SourceIP: "203.0.113.1"}})
	if len(rows) != 1 || rows[0].Count != 1 {
		t.Fatalf("original suppressed alert: %+v", rows)
	}
}

func TestCriticalIPPeriodUsesServerClock(t *testing.T) {
	a := testApp(t)
	a.appendEvent(Event{ID: "clock-ip", Time: time.Now().Add(-time.Minute), Message: `sshguard: Attack from "203.0.113.42" on service SSH with danger 2.`, Kind: "generic"})
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/events/critical-ips?period=24&to=2099-01-01T00:00:00Z", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "203.0.113.42") {
		t.Fatal(w.Code, w.Body.String())
	}
}
