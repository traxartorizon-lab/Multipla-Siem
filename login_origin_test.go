package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginFormOriginPolicy(t *testing.T) {
	a := testApp(t)
	a.demo = true
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, httptest.NewRequest("GET", a.origin+"/", nil))
	if w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("native form Origin would be suppressed")
	}
	for _, path := range []string{"/auth/local", "/auth/password"} {
		for _, origin := range []string{"", "null", "https://attacker.example", a.origin} {
			r := httptest.NewRequest("POST", a.origin+path, strings.NewReader("token=test&email=test@example.com&password=test"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			a.routes().ServeHTTP(w, r)
			if origin != a.origin && (w.Code != 403 || !strings.Contains(w.Body.String(), "origem inválida")) {
				t.Fatalf("unsafe origin accepted: %s %s %d", path, origin, w.Code)
			}
			if origin == a.origin && strings.Contains(w.Body.String(), "origem inválida") {
				t.Fatalf("same-origin form rejected: %s", path)
			}
		}
	}
}
