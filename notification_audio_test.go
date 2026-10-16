package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNotificationAudioViewsRefreshPolicyWithoutClearing(t *testing.T) {
	a := testApp(t)
	request := featureRequest(a, "admin@gmail.com", "POST", "/api/desktop/grants", []byte(`{"name":"audio fixture"}`))
	request.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, request)
	var grant struct{ Key string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &grant) != nil || grant.Key == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	key := descriptionKey("disk error")
	a.state.Notifications = []SystemNotification{
		{ID: "capacity", Time: time.Now(), Title: "Capacidade da coleta", Severity: "critical"},
		{ID: "event", EventID: "e", Time: time.Now(), Severity: "critical", Focus: &EventFocus{Pattern: key}},
	}
	for _, enabled := range []bool{true, false} {
		a.state.CriticalPatterns = map[string]CriticalPattern{key: {Critical: true, Sound: enabled, SoundType: "beep"}}
		for _, path := range []string{"/api/notifications", "/api/desktop/notifications"} {
			r := featureRequest(a, "admin@gmail.com", "GET", path, nil)
			if path == "/api/desktop/notifications" {
				r = httptest.NewRequest("GET", path, nil)
				r.TLS = &tls.ConnectionState{}
				r.Header.Set("Authorization", "Bearer "+grant.Key)
			}
			w = httptest.NewRecorder()
			a.routes().ServeHTTP(w, r)
			var response struct {
				Notifications []SystemNotification `json:"notifications"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Notifications) != 2 {
				t.Fatal(path, w.Code, w.Body.String())
			}
			for _, n := range response.Notifications {
				if n.Read || n.Continuous || n.ID == "capacity" && n.Sound || n.ID == "event" && n.Sound != enabled {
					t.Fatal(path, enabled, n)
				}
			}
		}
	}
	if len(a.state.Notifications) != 2 {
		t.Fatal("mute removed notifications")
	}
}

func TestNotificationAudioRequiresCurrentOptInAndAuthenticIsolation(t *testing.T) {
	a := testApp(t)
	key := descriptionKey("disk error")
	event := SystemNotification{ID: "event-a", EventID: "a", Severity: "critical", Focus: &EventFocus{Pattern: key}, Time: time.Now()}
	if a.notificationAudio(event).Sound {
		t.Fatal("unconfigured critical inherited audio")
	}
	a.state.CriticalPatterns = map[string]CriticalPattern{key: {Critical: true, Sound: true, SoundType: "beep"}}
	if n := a.notificationAudio(event); !n.Sound || n.SoundType != "beep" || n.Continuous {
		t.Fatal(n)
	}
	a.state.CriticalPatterns[key] = CriticalPattern{Critical: true, Sound: false, SoundType: "siren"}
	if a.notificationAudio(event).Sound {
		t.Fatal("individual disable ignored")
	}
	a.state.CriticalPatterns[key] = CriticalPattern{Critical: false, Sound: false}
	if a.notificationAudio(event).Sound {
		t.Fatal("deleted policy ignored")
	}
	capacity := SystemNotification{ID: "capacity", Title: "Capacidade da coleta", Severity: "critical", Continuous: true, Sound: true, IsolationIP: "100.86.221.98"}
	if n := a.notificationAudio(capacity); n.Sound || n.Continuous || n.Severity != "critical" {
		t.Fatal("operational warning impersonated isolation", n)
	}
	isolation := event
	isolation.IsolationIP = "100.86.221.98"
	isolation.Focus = &EventFocus{Detector: "direct-siem-isolation", Pattern: key}
	if n := a.notificationAudio(isolation); !n.Sound || !n.Continuous || n.SoundType != "siren" {
		t.Fatal("direct isolation policy lost", n)
	}
	invasion := event
	invasion.Focus = &EventFocus{Detector: "ssh-login-burst", Pattern: "other"}
	if n := a.notificationAudio(invasion); !n.Sound || n.Continuous || n.SoundType != "siren" {
		t.Fatal("invasion policy lost", n)
	}
	a.state.CriticalPatterns["other"] = CriticalPattern{Critical: true, Sound: false}
	if a.notificationAudio(invasion).Sound {
		t.Fatal("invasion explicit opt-out ignored")
	}
	if capacity.Read || event.Read {
		t.Fatal("sound evaluation changed read state")
	}
}
