package main

import (
	"crypto/tls"
	"encoding/json"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricKeysScopedRevocableAndRequireTLS(t *testing.T) {
	a := testApp(t)
	a.cfg.Devices = append(a.cfg.Devices, Device{Name: "PC", IP: "192.168.1.20", Kind: "windows"})
	a.demo = false
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/devices/metrics-key", []byte(`{"ip":"192.168.1.20"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	key := response["key"]
	if key == "" || a.state.MetricKeys["192.168.1.20"] == key {
		t.Fatal("key absent or plaintext stored")
	}
	send := func(ip, key string, secure bool) int {
		r := httptest.NewRequest("POST", "/api/device-metrics/"+ip, strings.NewReader(`{"hostname":"PC-TEST","cpu":12,"memory":40,"disks":[{"drive":"C:","used_percent":20}],"receive_bytes_per_second":100,"send_bytes_per_second":20}`))
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("Content-Type", "application/json")
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		out := httptest.NewRecorder()
		a.routes().ServeHTTP(out, r)
		return out.Code
	}
	if send("192.168.1.20", key, false) != 403 || send("192.168.1.1", key, true) != 401 || send("192.168.1.20", "invalid", true) != 401 {
		t.Fatal("credential scope/TLS")
	}
	if code := send("192.168.1.20", key, true); code != 200 {
		t.Fatal("valid metrics denied", code)
	}
	if send("192.168.1.20", key, true) != 429 {
		t.Fatal("rate limit")
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/devices/metrics-key", []byte(`{"ip":"192.168.1.20","revoke":true}`)))
	if w.Code != 200 || send("192.168.1.20", key, true) != 401 {
		t.Fatal("revocation")
	}
}
func TestMetricPayloadLimits(t *testing.T) {
	good := DeviceTelemetry{Hostname: "PC-TEST", CPU: 1, Memory: 10}
	if validateDeviceTelemetry(good) != nil {
		t.Fatal("valid payload")
	}
	for _, n := range []float64{-1, 101, math.Inf(1), math.NaN()} {
		bad := good
		bad.CPU = n
		if validateDeviceTelemetry(bad) == nil {
			t.Fatal("invalid percentage")
		}
	}
	bad := good
	bad.Hostname = "password=secret"
	if validateDeviceTelemetry(bad) == nil {
		t.Fatal("arbitrary data accepted")
	}
	bad = good
	bad.Disks = make([]DeviceDiskMetric, 33)
	if validateDeviceTelemetry(bad) == nil {
		t.Fatal("unbounded disks")
	}
}

func TestLinuxCollectorDownloadAndDisks(t *testing.T) {
	a := testApp(t)
	for _, platform := range []string{"linux", "windows", "invalid"} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/devices/collector?platform="+platform, nil))
		if platform == "invalid" {
			if w.Code != 400 {
				t.Fatal(w.Code)
			}
			continue
		}
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if platform == "linux" && (strings.Contains(w.Body.String(), "__COLLECTOR_BODY__") || !strings.Contains(w.Body.String(), "DynamicUser=yes") || !strings.Contains(w.Body.String(), "class NoRedirect")) {
			t.Fatal("incomplete Linux installer")
		}
	}
	m := DeviceTelemetry{Hostname: "linux-host", Disks: []DeviceDiskMetric{{Drive: "/", UsedPercent: 50}, {Drive: "/var/data", UsedPercent: 20}}}
	if err := validateDeviceTelemetry(m); err != nil {
		t.Fatal(err)
	}
	m.Disks[0].Drive = "/bad\npath"
	if validateDeviceTelemetry(m) == nil {
		t.Fatal("control character accepted")
	}
}
