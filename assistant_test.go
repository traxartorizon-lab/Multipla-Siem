package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAssistantPlannerRejectsUnboundedActions(t *testing.T) {
	valid := AssistantPlan{Action: "search", Client: "Multipla", Hours: 24, Query: "attack"}
	if err := validateAssistantPlan(valid, []string{"Multipla"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []AssistantPlan{{Action: "execute", Hours: 24}, {Action: "search", Client: "Other", Hours: 24}, {Action: "search", Hours: 745}, {Action: "answer", Hours: 24}, {Action: "search", Hours: 24, Query: strings.Repeat("x", 129)}} {
		if validateAssistantPlan(p, []string{"Multipla"}) == nil {
			t.Fatal("unsafe plan", p)
		}
	}
}
func TestAssistantQueriesKeepClientBoundaryAndRequireCSRF(t *testing.T) {
	a := testApp(t)
	a.cfg.Devices = []Device{{Name: "A", IP: "192.0.2.1", Kind: "pfsense", Client: "Alpha"}, {Name: "B", IP: "192.0.2.2", Kind: "pfsense", Client: "Beta"}}
	now := time.Now().UTC()
	for _, d := range a.cfg.Devices {
		a.appendEvent(Event{ID: d.Name, Time: now.Add(-time.Minute), Device: d.Name, SenderIP: d.IP, Message: "attack password=secret-value", Level: 12, Alert: true})
	}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	body, _ := json.Marshal(map[string]any{"filter": AssistantFilter{Client: "Alpha", Query: "attack", From: now.Add(-time.Hour).Format(time.RFC3339Nano), To: now.Format(time.RFC3339Nano)}, "report": true, "offset": 0})
	request := featureRequest(a, "admin@gmail.com", "POST", "/api/assistant/query", body)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, request)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result AssistantResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Matched != 1 || len(result.Events) != 1 || result.Events[0].Device != "A" || strings.Contains(w.Body.String(), "secret-value") || result.AnalysisError == "" {
		t.Fatal("boundary/redaction/fallback", w.Body.String())
	}
	bad := featureRequest(a, "admin@gmail.com", "POST", "/api/assistant/query", body)
	bad.Header.Del("X-CSRF-Token")
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, bad)
	if w.Code != 403 {
		t.Fatal("CSRF", w.Code)
	}
	anonymous := httptest.NewRequest("POST", "/api/assistant/query", bytes.NewReader(body))
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, anonymous)
	if w.Code != 401 {
		t.Fatal("anonymous", w.Code)
	}
	body = bytes.ReplaceAll(body, []byte("Alpha"), []byte("Unknown"))
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/assistant/query", body))
	if w.Code != 400 {
		t.Fatal("unknown client", w.Code)
	}
}
func TestAssistantInferenceLoopbackAndInvalidOutput(t *testing.T) {
	old := localAIHTTP
	defer func() { localAIHTTP = old }()
	content := `{"answer":"Resposta para revisão"}`
	localAIHTTP = &http.Client{Transport: aiRoundTripper(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.String() != localAIURL+"/api/chat" || bytes.Contains(b, []byte(`"tools"`)) {
			t.Fatal("unsafe inference")
		}
		output, _ := json.Marshal(map[string]any{"done": true, "message": map[string]string{"content": content}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(output))}, nil
	})}
	var out struct {
		Answer string `json:"answer"`
	}
	if err := assistantInference(context.Background(), defaultAIModel, assistantSafety, map[string]string{"question": "Teste"}, &out); err != nil || out.Answer == "" {
		t.Fatal(err)
	}
	content = `{"answer":"test","execute":"rm"}`
	if assistantInference(context.Background(), defaultAIModel, assistantSafety, nil, &out) == nil {
		t.Fatal("unknown field accepted")
	}
	if assistantInference(context.Background(), "remote:cloud", assistantSafety, nil, &out) == nil {
		t.Fatal("cloud accepted")
	}
}

func TestAssistantPlanUsesCurrentModelAndRejectsInjectedAction(t *testing.T) {
	a := testApp(t)
	a.cfg.Devices[0].Client = "Multipla"
	a.aiStatus.Ready = true
	a.state.LocalAIModel = "qwen3:4b"
	old := localAIHTTP
	defer func() { localAIHTTP = old }()
	modelContent := `{"action":"search","client":"Multipla","query":"attack","hours":24,"critical":false,"answer":"Confirme os filtros"}`
	localAIHTTP = &http.Client{Transport: aiRoundTripper(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("hidden-secret")) || !bytes.Contains(body, []byte("qwen3:4b")) {
			t.Fatal("secret or wrong model", string(body))
		}
		data, _ := json.Marshal(map[string]any{"done": true, "message": map[string]string{"content": modelContent}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data))}, nil
	})}
	body := []byte(`{"question":"Mostre attack do cliente Multipla","page":"events","context":"password=hidden-secret"}`)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/assistant/plan", body))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "qwen3:4b") {
		t.Fatal(w.Code, w.Body.String())
	}
	modelContent = `{"action":"execute","client":"Multipla","hours":24,"answer":"Executar comando"}`
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/assistant/plan", body))
	if w.Code != 502 {
		t.Fatal("injected action accepted", w.Code)
	}
}
func TestHostUsageRetentionGapsAndLowDisk(t *testing.T) {
	now := time.Now().UTC()
	cpu := 42.0
	samples := retainHostUsage([]HostUsageSample{{Time: now.Add(-25 * time.Hour), CPU: &cpu}, {Time: now.Add(-time.Minute), CPU: &cpu}, {Time: now.Add(-50 * time.Second), CPU: &cpu}, {Time: now.Add(time.Hour), CPU: &cpu}}, now)
	if len(samples) < 1 || len(samples) > 2 {
		t.Fatal(samples)
	}
	a := testApp(t)
	if err := a.recordHostUsage(a.cfg.DataDir, HostHealth{Time: now, CPU: &cpu}); err != nil {
		t.Fatal(err)
	}
	stored, err := readHostUsage(filepath.Join(a.cfg.DataDir, "host-usage.json"))
	if err != nil || len(stored) != 1 || stored[0].Memory != nil {
		t.Fatal("history", stored, err)
	}
	disk := 50.0
	free := uint64(500 << 20)
	h := HostHealth{Time: now, Disk: &disk, DiskFreeBytes: &free}
	a.updateHostConditions(h)
	a.updateHostConditions(h)
	if len(a.state.Notifications) != 1 || !a.state.HostConditions["Disco"] {
		t.Fatal("low disk did not dedupe", a.state.Notifications)
	}
	free = 2 << 30
	a.updateHostConditions(h)
	if len(a.state.Notifications) != 2 || a.state.HostConditions["Disco"] {
		t.Fatal("disk recovery", a.state.Notifications)
	}
}
