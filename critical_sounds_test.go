package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCriticalSoundManagement(t *testing.T) {
	a := testApp(t)
	e := Event{ID: "sound-seed", Time: time.Now().UTC(), Message: "disk failure", Device: "Proxmox", Level: 15}
	a.appendEvent(e)
	call := func(method, url, body string, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", method, url, []byte(body)))
		if w.Code != want {
			t.Fatalf("%s %s: %d %s", method, url, w.Code, w.Body.String())
		}
	}
	call("PUT", "/api/events/sound-seed/critical-pattern", `{"critical":true,"sound":true,"sound_type":"siren"}`, 200)
	key := descriptionKey(e.Message)
	if a.classifiedEvent(e).Classification.SoundType != "siren" {
		t.Fatal("selected sound missing")
	}
	call("PUT", "/api/critical-sounds/"+key, `{"sound":false,"sound_type":"beep"}`, 200)
	p := a.classifiedEvent(e)
	if !p.Classification.Critical || p.Classification.Sound || p.Classification.SoundType != "beep" {
		t.Fatal("mute changed classification", p)
	}
	call("PUT", "/api/critical-sounds/"+key, `{"sound":true,"sound_type":"invalid"}`, 400)
	loaded, err := newApp(a.cfg, a.configPath, false)
	if err != nil || loaded.state.CriticalPatterns[key].SoundType != "beep" {
		t.Fatal("persistence", err)
	}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	call("DELETE", "/api/critical-sounds/"+key, "", 403)
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "admin"}}
	call("DELETE", "/api/critical-sounds/"+key, "", 200)
	if a.classifiedEvent(e).Classification.Critical || a.events[0].Message != e.Message {
		t.Fatal("delete did not suppress or evidence changed")
	}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/critical-sounds", nil))
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal("deleted listed", w.Body.String())
	}
}
