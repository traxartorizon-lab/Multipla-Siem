package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestWOLPacketAndValidation(t *testing.T) {
	p, err := magicPacket("00:11:22:33:44:55")
	if err != nil || len(p) != 102 || !bytes.Equal(p[:6], bytes.Repeat([]byte{255}, 6)) {
		t.Fatal("bad magic packet")
	}
	for i := 0; i < 16; i++ {
		if !bytes.Equal(p[6+i*6:12+i*6], []byte{0, 17, 34, 51, 68, 85}) {
			t.Fatal("wrong MAC payload")
		}
	}
	for _, mac := range []string{"", "ff:ff:ff:ff:ff:ff", "01:11:22:33:44:55", "00:00:00:00:00:00", "00:11:22:33:44:55:66:77", ";reboot"} {
		if _, err = magicPacket(mac); err == nil {
			t.Fatal("invalid MAC", mac)
		}
	}
	for _, target := range []string{"127.0.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1", "example.com", "192.168.1.255; reboot"} {
		if validateDeviceNetwork(Device{WOLTarget: target}) == nil {
			t.Fatal("invalid destination", target)
		}
	}
	if err = validateDeviceNetwork(Device{MAC: "00:11:22:33:44:55", WOLTarget: "192.168.1.255"}); err != nil {
		t.Fatal(err)
	}
}
func TestDeviceActionsRequireAdministratorAndRegisteredIP(t *testing.T) {
	a := testApp(t)
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	for _, path := range []string{"/api/devices/network", "/api/system/reboot"} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", path, []byte(`{"ip":"192.168.1.1","action":"inspect"}`)))
		if w.Code != 403 {
			t.Fatal("viewer action", path, w.Code)
		}
	}
	a.state.Accounts["admin@gmail.com"] = AccessAccount{Role: "admin"}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/devices/network", []byte(`{"ip":"192.168.1.200","action":"inspect"}`)))
	if w.Code != 404 {
		t.Fatal("unregistered target accepted", w.Code)
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/system/reboot", []byte(`{"confirm":"yes"}`)))
	if w.Code != 400 {
		t.Fatal("missing reboot confirmation", w.Code)
	}
}
func TestDashboardDistributionCutoffAndOriginalLogs(t *testing.T) {
	a := testApp(t)
	now := time.Now().UTC()
	events := []Event{{Time: now.Add(-25 * time.Hour), Device: "outside"}, {Time: now.Add(-time.Hour), Device: "PC"}, {Time: now.Add(-time.Hour), Device: "PC", Alert: true}}
	for _, e := range events {
		f, err := os.OpenFile(a.journalPath(e.Time), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		json.NewEncoder(f).Encode(e)
		f.Close()
	}
	report, err := a.buildReport(httptest.NewRequest("GET", "/", nil), reportFilter{Type: "logs", cutoff: now.Add(-24 * time.Hour)}, now.Add(-24*time.Hour).Truncate(24*time.Hour), now.Truncate(24*time.Hour))
	if err != nil || report.Originals != 1 || report.ByDevice["outside"] != 0 || report.ByDevice["PC"] != 1 {
		t.Fatal("inaccurate distribution", report, err)
	}
}
