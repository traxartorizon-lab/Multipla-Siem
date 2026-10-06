package main

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestBundledAlertAudioRoutes(t *testing.T) {
	a := testApp(t)
	for _, name := range []string{"beep", "siren"} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, httptest.NewRequest("GET", "/audio/alert-"+name+".ogg", nil))
		if w.Code != 200 || w.Header().Get("Content-Type") != "audio/ogg" || !bytes.HasPrefix(w.Body.Bytes(), []byte("OggS")) {
			t.Fatalf("invalid sound %s: %d", name, w.Code)
		}
	}
}

func TestFaviconRoutes(t *testing.T) {
	a := testApp(t)
	for _, extension := range []string{"svg", "ico"} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, httptest.NewRequest("GET", "/favicon."+extension, nil))
		expected := "image/svg+xml"
		if extension == "ico" {
			expected = "image/x-icon"
		}
		if w.Code != 200 || w.Header().Get("Content-Type") != expected || w.Body.Len() < 50 {
			t.Fatalf("favicon %s not served", extension)
		}
	}
	for _, page := range []string{"index.html", "login.html"} {
		raw, err := assets.ReadFile("web/" + page)
		if err != nil || !bytes.Contains(raw, []byte(`href="/favicon.svg"`)) || !bytes.Contains(raw, []byte(`href="/favicon.ico"`)) {
			t.Fatal("missing icon reference", page)
		}
	}
}
