package main

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238TruncationAndReplay(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		at   int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if got := totp(secret, tc.at/30); got != tc.code {
			t.Fatal(tc, got)
		}
		n, ok := verifyTOTP(secret, tc.code, time.Unix(tc.at, 0), -1)
		if !ok {
			t.Fatal("valid code rejected")
		}
		if _, ok = verifyTOTP(secret, tc.code, time.Unix(tc.at, 0), n); ok {
			t.Fatal("code replay accepted")
		}
	}
}

func TestMFABlocksFirstFactorUntilEnrollmentAndVerification(t *testing.T) {
	t.Setenv("BACKUP_ENCRYPTION_KEY", fmt.Sprintf("%x", sha256.Sum256([]byte(token()))))
	a := testApp(t)
	required := true
	a.cfg.RequireMFA = &required
	a.sessions["pending"] = Session{Email: "admin@gmail.com", CSRF: "proof", Created: time.Now(), Expires: time.Now().Add(time.Hour)}
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "pending"})
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.origin)
		r.Header.Set("X-CSRF-Token", "proof")
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/snapshot", ""); w.Code != 401 {
		t.Fatal("first factor granted access", w.Code)
	}
	w := call("POST", "/auth/mfa/enroll", `{}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var setup map[string]string
	json.Unmarshal(w.Body.Bytes(), &setup)
	if a.state.MFA["admin@gmail.com"].EncryptedSecret != "" {
		t.Fatal("secret active before proof")
	}
	code := totp(setup["secret"], time.Now().Unix()/30)
	w = call("POST", "/auth/mfa/verify", `{"code":"`+code+`"}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(a.state.MFA["admin@gmail.com"].EncryptedSecret, setup["secret"]) {
		t.Fatal("plaintext secret persisted")
	}
	if w := call("GET", "/api/snapshot", ""); w.Code != 200 {
		t.Fatal("MFA did not grant access", w.Code)
	}
	if w := call("POST", "/auth/mfa/step-up", `{"code":"`+code+`"}`); w.Code != 403 {
		t.Fatal("replay accepted", w.Code)
	}
	s := a.sessions["pending"]
	s.MFATime = time.Now().Add(-6 * time.Minute)
	a.sessions["pending"] = s
	if w := call("POST", "/api/system/reboot", `{}`); w.Code != 428 {
		t.Fatal("sensitive operation without step-up", w.Code)
	}
}

func TestMFAEncryptionIsBoundToAccount(t *testing.T) {
	t.Setenv("BACKUP_ENCRYPTION_KEY", fmt.Sprintf("%x", sha256.Sum256([]byte(token()))))
	cipher, err := sealMFA("alpha@example.com", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = openMFA("beta@example.com", cipher); err == nil {
		t.Fatal("another account decrypted MFA")
	}
}

func TestMFARejectsExpiredIdleSession(t *testing.T) {
	a := testApp(t)
	a.sessions["idle"] = Session{Email: "admin@gmail.com", Created: time.Now().Add(-time.Hour), MFATime: time.Now().Add(-20 * time.Minute), Expires: time.Now().Add(time.Hour)}
	a.active["idle"] = time.Now().Add(-16 * time.Minute)
	r := httptest.NewRequest("GET", "/auth/mfa/status", nil)
	r.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "idle"})
	if _, _, ok := a.mfaSession(r); ok {
		t.Fatal("MFA revived an idle expired session")
	}
}
