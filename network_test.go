package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetworkEquipmentPersistsAndTestsAcceptOnlyRegisteredTargets(t *testing.T) {
	a := testApp(t)
	a.demo = true
	body := []byte(`{"name":"Switch Matriz","ip":"192.0.2.20","kind":"switch","client":"Cliente A","unit":"Matriz"}`)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/network/equipment", body))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var device NetworkEquipment
	json.Unmarshal(w.Body.Bytes(), &device)
	loaded, err := newApp(a.cfg, a.configPath, true)
	if err != nil || len(loaded.state.NetworkEquipment) != 1 || loaded.state.NetworkEquipment[0].Client != "Cliente A" {
		t.Fatal("network inventory not persisted", err)
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/network/tests", []byte(`{"ids":["192.0.2.99;id"],"mode":"quick"}`)))
	if w.Code != 400 {
		t.Fatal("arbitrary target accepted", w.Code)
	}
	request, _ := json.Marshal(map[string]any{"ids": []string{device.ID}, "mode": "quick"})
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/network/tests", request))
	if w.Code != 200 {
		t.Fatal("registered target rejected", w.Code, w.Body.String())
	}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	for _, tc := range []struct {
		method, path string
		body         []byte
		code         int
	}{{"GET", "/api/network", nil, 200}, {"PUT", "/api/network/equipment", body, 403}, {"POST", "/api/network/tests", request, 403}} {
		w = httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", tc.method, tc.path, tc.body))
		if w.Code != tc.code {
			t.Fatal("network role boundary", tc.method, w.Code)
		}
	}
	for _, ip := range []string{"127.0.0.1", "0.0.0.0", "224.0.0.1", "https://example.com", "192.0.2.1; id", "fe80::1%eth0"} {
		device.IP = ip
		if validateEquipment(device) == nil {
			t.Fatal("invalid management address accepted", ip)
		}
	}
	if strings.Contains(strings.Join([]string{device.Name, device.Client}, ""), "secret") {
		t.Fatal("unexpected fixture")
	}
}
