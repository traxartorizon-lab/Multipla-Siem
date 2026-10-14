package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMFAQRStableSessionAndIndependentEnrollment(t *testing.T) {
	t.Setenv("BACKUP_ENCRYPTION_KEY", fmt.Sprintf("%x", sha256.Sum256([]byte(token()))))
	a := testApp(t)
	required := true
	a.cfg.RequireMFA = &required
	for _, id := range []string{"first", "second"} {
		a.sessions[id] = Session{Email: "admin@gmail.com", CSRF: "proof", Created: time.Now(), Expires: time.Now().Add(time.Hour)}
	}
	call := func(id, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Origin", a.origin)
		r.Header.Set("X-CSRF-Token", "proof")
		r.Header.Set("Content-Type", "application/json")
		if id != "" {
			r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: id})
		}
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		return w
	}
	enroll := func(id string) map[string]string {
		w := call(id, "POST", "/auth/mfa/enroll", "{}")
		if w.Code != 200 {
			t.Fatalf("enrollment: %d", w.Code)
		}
		var s map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	first := enroll("first")
	again := enroll("first")
	if first["secret"] != again["secret"] || first["expires_at"] != again["expires_at"] {
		t.Fatal("reload rotated enrollment or extended its expiry")
	}
	second := enroll("second")
	if second["secret"] == first["secret"] {
		t.Fatal("sessions shared secret")
	}
	u, err := url.Parse(first["uri"])
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("secret") != first["secret"] || u.Query().Get("issuer") != "Multipla SIEM" || u.Query().Get("digits") != "6" || u.Query().Get("period") != "30" || u.Query().Get("algorithm") != "SHA1" {
		t.Fatal("invalid authenticator URI")
	}
	qr := call("first", "GET", first["qr"], "")
	if qr.Code != 200 || qr.Header().Get("Content-Type") != "image/png" || qr.Header().Get("Cache-Control") != "no-store" || qr.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" {
		t.Fatal("QR response privacy or content invalid")
	}
	image, err := png.Decode(bytes.NewReader(qr.Body.Bytes()))
	if err != nil || image.Bounds().Dx() < 250 {
		t.Fatal("invalid QR PNG")
	}
	if w := call("", "GET", first["qr"], ""); w.Code == 200 {
		t.Fatal("anonymous QR disclosed")
	}
	r := httptest.NewRequest("GET", first["qr"], nil)
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "first"})
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-site QR disclosed")
	}
	code := totp(first["secret"], time.Now().Unix()/30)
	w = call("first", "POST", "/auth/mfa/verify", `{"code":"`+code+`"}`)
	if w.Code != 200 {
		t.Fatal("second session invalidated first enrollment", w.Code)
	}
	if len(a.mfaEnrollments) != 0 {
		t.Fatal("pending secrets left after activation")
	}
	if w := call("first", "GET", first["qr"], ""); w.Code == 200 {
		t.Fatal("enrolled secret displayed again")
	}
	if w := call("second", "GET", "/api/snapshot", ""); w.Code != 401 {
		t.Fatal("another session gained second factor")
	}
}

func TestMFAExpiredQRDoesNotRevealPendingSecret(t *testing.T) {
	a := testApp(t)
	a.sessions["expired"] = Session{Email: "admin@gmail.com", Created: time.Now().Add(-6 * time.Minute), Expires: time.Now().Add(time.Hour)}
	a.mfaEnrollments = map[string]MFAEnrollment{"expired": {Email: "admin@gmail.com", Session: "expired", Secret: "not-returned", Expires: time.Now().Add(-time.Minute)}}
	r := httptest.NewRequest("GET", "/auth/mfa/qr.png", nil)
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "expired"})
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code == 200 || strings.Contains(w.Body.String(), "not-returned") {
		t.Fatal("expired enrollment disclosed")
	}
}
