package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRulePreviewAuthenticatedAndReadOnly(t *testing.T) {
	a := testApp(t)
	a.events = []Event{{Kind: "pfsense", Message: "blocked"}, {Kind: "proxmox", Message: "blocked"}}
	a.sessions["test"] = Session{Email: "admin@gmail.com", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	for _, tc := range []struct {
		body string
		auth bool
		code int
	}{{`{"pattern":"blocked","kind":"pfsense","message":"blocked"}`, false, 401}, {`{"pattern":"[","kind":"any"}`, true, 400}, {`{"pattern":"blocked","kind":"pfsense","message":"blocked"}`, true, 200}} {
		r := httptest.NewRequest("POST", a.origin+"/api/rules/test", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.origin)
		r.Header.Set("X-CSRF-Token", "csrf")
		if tc.auth {
			r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "test"})
		}
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatal(w.Code, w.Body.String())
		}
		if tc.code == 200 {
			var v struct {
				Matches int  `json:"matches"`
				Checked int  `json:"checked"`
				Sample  bool `json:"sample_match"`
			}
			json.Unmarshal(w.Body.Bytes(), &v)
			if v.Matches != 1 || v.Checked != 1 || !v.Sample {
				t.Fatal(v)
			}
		}
	}
	if len(a.state.Blocks) != 0 || len(a.state.Rules) != 3 {
		t.Fatal("preview mutated state")
	}
}
func TestEditBlockReasonPreservesExpiryAndCSRF(t *testing.T) {
	a := testApp(t)
	old := Block{IP: "198.51.100.33", Reason: "old", Mode: "simulated", Expires: time.Now().Add(time.Hour)}
	a.state.Blocks[old.IP] = old
	a.sessions["test"] = Session{Email: "admin@gmail.com", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	for _, csrf := range []string{"wrong", "csrf"} {
		r := httptest.NewRequest("PUT", a.origin+"/api/blocks/"+old.IP, strings.NewReader(`{"reason":"new"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "test"})
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		want := 200
		if csrf == "wrong" {
			want = 403
		}
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	b := a.state.Blocks[old.IP]
	if b.Reason != "new" || b.Expires != old.Expires || b.Mode != old.Mode {
		t.Fatal("edit altered expiry or publication")
	}
	loaded, e := newApp(a.cfg, a.configPath, false)
	if e != nil || loaded.state.Blocks[old.IP].Reason != "new" {
		t.Fatal("edit not persisted", e)
	}
}
