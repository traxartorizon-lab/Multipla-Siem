package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEveryCriticalHasDiagnosisWithoutCooldown(t *testing.T) {
	a := testApp(t)
	for _, message := range []string{"kernel panic password=hidden-secret", "out of memory: kill process 123", "zpool storage FAULTED", "<130>Unknown critical vendor event"} {
		e := Event{ID: token(), Time: time.Now(), Device: "Firewall", Message: message, Kind: "pfsense"}
		if !a.appendEvent(e) {
			t.Fatal("journal failure")
		}
		a.analyzeEvent(e)
	}
	if len(a.events) != 8 {
		t.Fatal("critical event suppressed", len(a.events))
	}
	for _, e := range a.events {
		if e.Diagnosis == nil || e.Diagnosis.Uncertainty == "" || strings.Contains(e.Diagnosis.Evidence, "hidden-secret") {
			t.Fatal("missing or unsafe diagnosis", e)
		}
	}
	unknown := localDiagnosis(Event{Alert: true, Level: 12, Message: "unknown vendor critical"})
	if !strings.Contains(unknown.Cause, "não identificou") {
		t.Fatal("invented cause")
	}
	if localDiagnosis(Event{Message: "<134>routine firewall pass"}) != nil {
		t.Fatal("normal syslog treated as critical")
	}
}
func TestAnalysisCannotBeDisabledThroughConfiguration(t *testing.T) {
	a := testApp(t)
	c := a.cfg
	c.LocalAnalysis = false
	body, _ := json.Marshal(c)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/config", body))
	if w.Code != 200 || !a.cfg.LocalAnalysis {
		t.Fatal("continuous analysis disabled", w.Code)
	}
	reloaded, err := newApp(c, a.configPath, false)
	if err != nil || !reloaded.cfg.LocalAnalysis || !reloaded.analysisSnapshot().Enabled {
		t.Fatal("analysis not active after reboot", err)
	}
}
func TestAlertEditingPreservesOriginalAndPersistsReview(t *testing.T) {
	a := testApp(t)
	event := Event{ID: token(), Time: time.Now(), Device: "Firewall", Alert: true, Level: 12, Rule: "Original", Message: "kernel panic"}
	if !a.appendEvent(event) {
		t.Fatal("journal")
	}
	journal, _ := os.ReadFile(a.journalPath(event.Time))
	data := []byte(`{"title":"Falha em investigação","level":10,"status":"investigating","notes":"Verificar hardware"}`)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/alerts/"+event.ID, data))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := os.ReadFile(a.journalPath(event.Time))
	if !bytes.Equal(journal, after) || a.events[0].Rule != "Original" || a.events[0].Level != 12 {
		t.Fatal("original evidence modified")
	}
	reloaded, err := newApp(a.cfg, a.configPath, false)
	if err != nil || reloaded.state.AlertReviews[event.ID].Status != "investigating" {
		t.Fatal("review not persisted", err)
	}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/alerts/"+event.ID, data))
	if w.Code != 403 {
		t.Fatal("viewer edited alert")
	}
}

type aiRoundTripper func(*http.Request) (*http.Response, error)

func (f aiRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestLocalAIUsesOnlyLoopbackAndRedactsOutput(t *testing.T) {
	previous := localAIHTTP
	defer func() { localAIHTTP = previous }()
	localAIHTTP = &http.Client{Transport: aiRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "127.0.0.1:11434" || r.URL.Path != "/api/chat" {
			t.Fatal("nonlocal inference", r.URL)
		}
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("hidden-secret")) || bytes.Contains(body, []byte(`"tools"`)) {
			t.Fatal("unsafe model request")
		}
		var request map[string]any
		if json.Unmarshal(body, &request) != nil || request["stream"] != false {
			t.Fatal("invalid chat request")
		}
		content := `{"summary":"Hipótese de erro","cause":"password=hidden-output","checks":["Verifique o processo"],"remediation":["Avalie os limites"],"uncertainty":"Confirme a hipótese"}`
		response, _ := json.Marshal(map[string]any{"done": true, "message": map[string]string{"content": content}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(response)), Header: http.Header{}}, nil
	})}
	e := Event{Level: 12, Message: "kernel panic password=hidden-secret"}
	e.Message = redact(e.Message)
	e.Diagnosis = localDiagnosis(e)
	result, err := generateLocalDiagnosis(e, defaultAIModel)
	if err != nil || strings.Contains(result.Cause, "hidden-output") || result.Model != defaultAIModel {
		t.Fatal("unsafe diagnosis", result, err)
	}
	for _, model := range []string{"qwen3:cloud", "gpt-cloud:latest", "https://evil.example/model", "../qwen:1"} {
		if safeLocalModel(model) {
			t.Fatal("remote model accepted", model)
		}
	}
}
