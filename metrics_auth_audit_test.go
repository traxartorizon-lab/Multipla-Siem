package main

import (
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditMetricsRejectRawCredential(t *testing.T) {
	a := testApp(t)
	a.demo = false
	a.cfg.Devices = append(a.cfg.Devices, Device{Name: "audit", IP: "192.0.2.20", Kind: "linux"})
	key := strings.Repeat("a", 43)
	a.state.MetricKeys = map[string]string{"192.0.2.20": metricTokenHash(key)}
	r := httptest.NewRequest("POST", "/api/device-metrics/192.0.2.20", strings.NewReader(`{"hostname":"audit","cpu":1,"memory":1,"disks":[]}`))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", key)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("raw credential accepted: status %d (expected 401)", w.Code)
	}
}
