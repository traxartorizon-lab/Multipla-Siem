package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAutomaticDHCPReportUpdatesWithoutExtendingRetention(t *testing.T) {
	a := testApp(t)
	j := &dhcpJob{id: "automatic", owner: "admin@gmail.com", started: time.Now().UTC(), status: "analyzing", servers: []DHCPServer{{IP: "192.168.10.1"}}}
	a.saveDHCPReport(j)
	if j.reportID == "" || j.reportError != "" || len(a.state.TemporaryReports) != 1 {
		t.Fatal("not persisted", j.reportError)
	}
	first := a.state.TemporaryReports[0]
	if first.Expires.Sub(first.Created) != 72*time.Hour {
		t.Fatal("retention")
	}
	j.status = "completed"
	j.message = "Consulta concluída"
	a.saveDHCPReport(j)
	if len(a.state.TemporaryReports) != 1 || a.state.TemporaryReports[0].ID != first.ID || !a.state.TemporaryReports[0].Expires.Equal(first.Expires) || a.state.TemporaryReports[0].Output != j.message {
		t.Fatal("update duplicated or extended report")
	}
	a.state.TemporaryReports = nil
	a.saveDHCPReport(j)
	if len(a.state.TemporaryReports) != 0 {
		t.Fatal("deleted report recreated")
	}
	j = &dhcpJob{id: "expired", owner: "admin@gmail.com", started: time.Now().Add(-73 * time.Hour)}
	a.saveDHCPReport(j)
	if j.reportError == "" || len(a.state.TemporaryReports) != 0 {
		t.Fatal("expired capture accepted")
	}
}

func TestTemporaryReportRetentionAndAccountBoundary(t *testing.T) {
	a := testApp(t)
	now := time.Now().UTC()
	a.state.TemporaryReports = []TemporaryReport{{ID: "expired", Owner: "admin@gmail.com", Expires: now.Add(-time.Second)}, {ID: "mine", Owner: "admin@gmail.com", Expires: now.Add(time.Hour)}, {ID: "other", Owner: "other@gmail.com", Expires: now.Add(time.Hour)}}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/test-reports", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "expired") || strings.Contains(w.Body.String(), "other") || !strings.Contains(w.Body.String(), "mine") {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(a.state.TemporaryReports) != 2 {
		t.Fatal("expired item not removed")
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "DELETE", "/api/test-reports/other", nil))
	if w.Code != 404 {
		t.Fatal("cross-account delete", w.Code)
	}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/test-reports", nil))
	if w.Code != 403 {
		t.Fatal("viewer exposure", w.Code)
	}
}
func TestTemporaryReportSavesKnownCompletedTestsOnlyAndRedacts(t *testing.T) {
	a := testApp(t)
	a.networkTests = map[string]*NetworkTest{"test": {ID: "test", Mode: "quick", Status: "completed", Started: time.Now().UTC(), Output: []string{"password=MY_SYNTHETIC_SECRET", "4 packets transmitted"}}}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/test-reports", []byte(`{"type":"network","id":"test"}`)))
	if w.Code != 200 || strings.Contains(w.Body.String(), "MY_SYNTHETIC_SECRET") {
		t.Fatal(w.Code, w.Body.String())
	}
	var saved TemporaryReport
	if json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.Expires.Sub(saved.Created) != 72*time.Hour {
		t.Fatal("retention interval")
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/test-reports", []byte(`{"type":"arbitrary-command","id":"test"}`)))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	a.mu.Lock()
	a.networkTests["test"].Status = "running"
	a.mu.Unlock()
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/test-reports", []byte(`{"type":"network","id":"test"}`)))
	if w.Code != 409 {
		t.Fatal("running saved", w.Code)
	}
}
