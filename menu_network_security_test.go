package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAccountMenuAssetAndHostAuthorization(t *testing.T) {
	a := testApp(t)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, httptest.NewRequest("GET", "/account-menu.js", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "javascript") || !strings.Contains(w.Body.String(), "account-menu-button") {
		t.Fatal("menu asset not served as JavaScript", w.Code, w.Header().Get("Content-Type"))
	}
	for _, group := range []string{groupAlerts, groupAdministrative, "legacy-viewer"} {
		a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Group: group, Role: "admin", Capabilities: []string{"accounts", "terminal", "backup"}}}
		if group == "legacy-viewer" {
			a.state.Accounts["admin@gmail.com"] = AccessAccount{Role: "viewer"}
		}
		for _, route := range []struct{ method, path, body string }{{"POST", "/api/system/reboot", `{"confirm":"REINICIAR"}`}, {"POST", "/api/system/update", `{"confirm":"ATUALIZAR"}`}, {"GET", "/api/system/update", ""}, {"POST", "/api/ssh/identity", `{"id":"__multipla_local_server__"}`}, {"POST", "/api/ssh/trust", `{"id":"__multipla_local_server__","key":"fake"}`}, {"POST", "/api/ssh/sessions", `{"id":"__multipla_local_server__","user":"multipla-ops"}`}} {
			w := httptest.NewRecorder()
			a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", route.method, route.path, []byte(route.body)))
			if w.Code != 403 {
				t.Fatalf("%s %s got %d", group, route.path, w.Code)
			}
		}
	}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Group: groupAdministrative, Role: "admin", Capabilities: []string{"accounts"}}}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/accounts", nil))
	if w.Code != 200 {
		t.Fatal("accounts grant broken", w.Code)
	}
}
func TestSyslogOriginAllowlistAndPerOriginQueue(t *testing.T) {
	a := testApp(t)
	if !a.syslogOriginAllowed("192.168.1.1") || a.syslogOriginAllowed("192.0.2.99") {
		t.Fatal("origin prefilter")
	}
	a.cfg.Devices = []Device{{IP: "192.0.2.5"}}
	a.refreshSyslogOriginsLocked()
	if a.syslogOriginAllowed("192.168.1.1") || !a.syslogOriginAllowed("192.0.2.5") {
		t.Fatal("changed origin snapshot")
	}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	q := newSyslogQueue(syslogQueueSlots, func(syslogPacket) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
	}, func(syslogPacket) {})
	defer q.close()
	q.enqueue("A", "first")
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker unavailable")
	}
	for i := 0; i < 64; i++ {
		if !q.enqueue("A", "x") {
			t.Fatal("per-origin prematurely full", i)
		}
	}
	if q.enqueue("A", "excess") {
		t.Fatal("one origin bypassed reservation")
	}
	if !q.enqueue("B", "preserved capacity") {
		t.Fatal("one origin exhausted all capacity")
	}
	q.close()
	close(release)
	<-q.finished
	if syslogOverflowDelta(^uint32(0)-2, 4) != 7 {
		t.Fatal("kernel overflow counter wrap")
	}
}
