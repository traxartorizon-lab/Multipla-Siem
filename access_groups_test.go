package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGroupsDenyHostAndIdentityOperations(t *testing.T) {
	for _, group := range []string{groupAlerts, groupAdministrative} {
		a := testApp(t)
		a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "admin", Group: group}}
		for _, route := range []struct{ method, path string }{{"GET", "/api/accounts"}, {"PUT", "/api/accounts"}, {"GET", "/api/backups"}, {"POST", "/api/backup/import"}, {"POST", "/api/ssh/sessions"}, {"POST", "/api/settings/google"}, {"POST", "/api/system/update"}, {"GET", "/api/system/update"}, {"POST", "/api/system/reboot"}} {
			w := httptest.NewRecorder()
			a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", route.method, route.path, []byte(`{}`)))
			if w.Code != 403 {
				t.Fatalf("%s %s: %d", group, route.path, w.Code)
			}
		}
	}
}

func TestAlertsSnapshotDoesNotLeakNormalLogsOrRules(t *testing.T) {
	a := testApp(t)
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Group: groupAlerts, Role: "viewer"}}
	a.events = []Event{{ID: "ordinary", Message: "private normal log", Level: 1}, {ID: "critical", Message: "critical alert", Level: 12}}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/snapshot", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "private normal log") || strings.Contains(w.Body.String(), "allowed_emails") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestGroupAssignmentPersistsAndLegacyIsExplicit(t *testing.T) {
	a := testApp(t)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/accounts", []byte(`{"email":"ops@example.com","group":"administrative"}`)))
	if w.Code != 200 || a.groupLocked("ops@example.com") != groupAdministrative {
		t.Fatal(w.Code, w.Body.String())
	}
	if a.groupLocked("admin@gmail.com") != groupSuperadmin {
		t.Fatal("legacy administrator lost access")
	}
	a.state.LocalAdmin.Email = "owner@example.com"
	a.state.Accounts["owner@example.com"] = AccessAccount{Group: groupAlerts}
	if a.groupLocked("owner@example.com") != groupSuperadmin {
		t.Fatal("primary owner lost recovery access")
	}
}

func TestAdministrativeConfigCannotEnrollAccounts(t *testing.T) {
	a := testApp(t)
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Group: groupAdministrative, Role: "admin"}}
	c := a.cfg
	c.AllowedEmails = []string{"attacker@example.com"}
	body, _ := json.Marshal(c)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/config", body))
	if w.Code != 200 || len(a.cfg.AllowedEmails) != 1 || a.cfg.AllowedEmails[0] != "admin@gmail.com" {
		t.Fatal("operation group altered account allowlist", w.Code, w.Body.String())
	}
}

func TestAlertAccountCannotResolvePlainEventFocus(t *testing.T) {
	a := testApp(t)
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Group: groupAlerts, Role: "viewer"}}
	a.events = []Event{{ID: "normal", Message: "ordinary-log-secret", Level: 1}}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/events/history?focus=normal", nil))
	if w.Code != 404 || strings.Contains(w.Body.String(), "ordinary-log-secret") {
		t.Fatal("normal focus exposed", w.Code, w.Body.String())
	}
}
