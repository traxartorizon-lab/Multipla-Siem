package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGoogleDesktopCallbackPreservesTicketAndShowsConsent(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "test-client")
	t.Setenv("GOOGLE_CLIENT_SECRET", "test-secret")
	a := testApp(t)
	a.origin = "https://siem.example"
	a.nativeTLS = true
	id, v := token(), token()
	a.desktopLogins = map[string]DesktopLogin{id: {Challenge: pkceChallenge(v), Expires: time.Now().Add(time.Minute)}}
	old := client
	defer func() { client = old }()
	client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		body := `{"access_token":"test-only"}`
		if strings.Contains(r.URL.Host, "openidconnect") {
			body = `{"sub":"google-sub","email":"admin@gmail.com","email_verified":true}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	r := httptest.NewRequest("GET", a.origin+"/auth/desktop/google?id="+id, nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatal("Google start", w.Code, w.Body.String())
	}
	google, _ := url.Parse(w.Header().Get("Location"))
	state := google.Query().Get("state")
	if a.oauth[state].DesktopID != id {
		t.Fatal("desktop association lost")
	}
	r = httptest.NewRequest("GET", a.origin+"/auth/callback?state="+state+"&code=test", nil)
	r.TLS = &tls.ConnectionState{}
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), desktopLoginCode(id)) || a.desktopLogins[id].Stage != "awaiting_consent" {
		t.Fatal("callback did not reach desktop confirmation", w.Code, w.Body.String())
	}
}

func TestDesktopLoginRequiresConsentPKCEAndSingleUse(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "test-client")
	t.Setenv("GOOGLE_CLIENT_SECRET", "test-secret")
	a := testApp(t)
	a.origin = "https://siem.example"
	a.nativeTLS = true
	call := func(method, path, body, ctype string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, a.origin+path, strings.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Content-Type", ctype)
		r.Header.Set("Origin", a.origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		return w
	}
	verifier := token()
	raw, _ := json.Marshal(map[string]string{"challenge": pkceChallenge(verifier)})
	w := call("POST", "/auth/desktop/start", string(raw), "application/json", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var start struct{ ID, Code, URL string }
	json.Unmarshal(w.Body.Bytes(), &start)
	proof := url.Values{"id": {start.ID}, "verifier": {verifier}}.Encode()
	if w := call("POST", "/auth/desktop/consume", proof, "application/x-www-form-urlencoded", nil); w.Code != 403 {
		t.Fatal("unapproved session created")
	}
	r := httptest.NewRequest("GET", a.origin+"/auth/callback", nil)
	r.TLS = &tls.ConnectionState{}
	consent := httptest.NewRecorder()
	a.desktopLoginConsent(consent, r, start.ID, "admin@gmail.com", "google-subject")
	if consent.Code != 200 || !strings.Contains(consent.Body.String(), start.Code) {
		t.Fatal("confirmation unavailable")
	}
	if consent.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("confirmation form suppresses its POST origin")
	}
	flow := a.desktopLogins[start.ID]
	cookie := consent.Result().Cookies()[0]
	approve := url.Values{"id": {start.ID}, "consent": {flow.Consent}}.Encode()
	for _, origin := range []string{"null", "", "https://attacker.example"} {
		r := httptest.NewRequest("POST", a.origin+"/auth/desktop/approve", strings.NewReader(approve))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 403 || a.desktopLogins[start.ID].Approved {
			t.Fatal("approval accepted untrusted origin", origin, w.Code)
		}
	}
	if w := call("POST", "/auth/desktop/approve", approve, "application/x-www-form-urlencoded", nil); w.Code != 403 {
		t.Fatal("approval without browser binding")
	}
	if w := call("POST", "/auth/desktop/approve", approve, "application/x-www-form-urlencoded", cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	wrong := url.Values{"id": {start.ID}, "verifier": {token()}}.Encode()
	if w := call("POST", "/auth/desktop/consume", wrong, "application/x-www-form-urlencoded", nil); w.Code != 403 {
		t.Fatal("wrong PKCE accepted")
	}
	w = call("POST", "/auth/desktop/consume", proof, "application/x-www-form-urlencoded", nil)
	if w.Code != 303 || len(w.Result().Cookies()) == 0 {
		t.Fatal("session not delivered to WebView", w.Code, w.Body.String())
	}
	if w := call("POST", "/auth/desktop/consume", proof, "application/x-www-form-urlencoded", nil); w.Code != 403 {
		t.Fatal("replay accepted")
	}
}

func TestDesktopLoginRejectsExpiredAndChangedAccounts(t *testing.T) {
	a := testApp(t)
	v := token()
	id := token()
	a.desktopLogins = map[string]DesktopLogin{id: {Challenge: pkceChallenge(v), Email: "admin@gmail.com", Subject: "sub", Approved: true, Expires: time.Now().Add(time.Minute), AccountDigest: a.desktopAccountDigest("admin@gmail.com")}}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Group: groupAlerts, Role: "viewer"}}
	r := httptest.NewRequest("POST", "/auth/desktop/consume", strings.NewReader(url.Values{"id": {id}, "verifier": {v}}.Encode()))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("privilege change accepted", w.Code)
	}
}
