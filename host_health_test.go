package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHostProcParsing(t *testing.T) {
	total, idle, cores, err := parseHostCPU("cpu 10 0 20 70 5 0 0 0 10 0\ncpu0 1\ncpu1 2\n")
	if err != nil || total != 105 || idle != 75 || cores != 2 {
		t.Fatal(total, idle, cores, err)
	}
	ram, err := parseHostMemory("MemTotal: 1000 kB\nMemAvailable: 200 kB\n")
	if err != nil || ram != 80 {
		t.Fatal(ram, err)
	}
	if _, err := parseHostMemory("MemTotal: 0 kB"); err == nil {
		t.Fatal("missing RAM accepted")
	}
}
func TestHostNotificationConditionsHysteresisAndPersonalClear(t *testing.T) {
	a := testApp(t)
	v := 91.0
	h := HostHealth{Time: time.Now().Add(-time.Second), CPU: &v}
	a.updateHostConditions(h)
	a.updateHostConditions(h)
	if len(a.state.Notifications) != 1 {
		t.Fatal("repeated high notice")
	}
	v = 87
	a.updateHostConditions(h)
	if len(a.state.Notifications) != 1 {
		t.Fatal("hysteresis")
	}
	v = 80
	a.updateHostConditions(h)
	if len(a.state.Notifications) != 2 {
		t.Fatal("recovery")
	}
	a.hostHealth = h
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]time.Time{"through": h.Time})
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/notifications/clear", body))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	_, unread := notificationView(a.state.Notifications, a.state.NotificationsCleared["admin@gmail.com"])
	_, other := notificationView(a.state.Notifications, time.Time{})
	if unread != 0 || other != 2 || len(a.state.Notifications) != 2 {
		t.Fatal("clear removed shared history")
	}
	loaded, err := newApp(a.cfg, a.configPath, false)
	if err != nil || len(loaded.state.Notifications) != 2 {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	request := featureRequest(a, "admin@gmail.com", "POST", "/api/notifications/clear", body)
	request.Header.Del("X-CSRF-Token")
	a.routes().ServeHTTP(w, request)
	if w.Code != 403 {
		t.Fatal("clear CSRF bypass")
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/system/health", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
