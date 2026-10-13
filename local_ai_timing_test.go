package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDiagnosisBudgetStartsAfterInferenceSlot(t *testing.T) {
	old := localAIHTTP
	defer func() { localAIHTTP = old }()
	localInferenceSlot <- struct{}{}
	released := make(chan time.Time, 1)
	go func() { time.Sleep(10 * time.Millisecond); released <- time.Now(); <-localInferenceSlot }()
	localAIHTTP = &http.Client{Timeout: 90 * time.Second, Transport: aiRoundTripper(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		releaseTime := <-released
		if !ok || deadline.Before(releaseTime.Add(localDiagnosisTimeout)) {
			t.Fatal("generation budget consumed while waiting for inference slot", deadline, releaseTime)
		}
		var body struct {
			Options struct {
				Threads int `json:"num_thread"`
				Context int `json:"num_ctx"`
				Predict int `json:"num_predict"`
			} `json:"options"`
		}
		if json.NewDecoder(request.Body).Decode(&body) != nil || body.Options.Threads != min(runtime.NumCPU(), 4) || body.Options.Context != 3072 || body.Options.Predict != 600 {
			t.Fatal("unexpected CPU or memory settings", body)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"done":true,"message":{"content":"{\"summary\":\"Hipótese para revisão\"}"}}`))}, nil
	})}
	_, err := generateLocalDiagnosis(Event{Message: "test event"}, "qwen3:4b-instruct")
	if err != nil {
		t.Fatal(err)
	}
	if len(localInferenceSlot) != 0 || localAIHTTP.Timeout != 90*time.Second {
		t.Fatal("slot leaked or shared client changed")
	}
}

func TestDiagnosisCancellationWhileWaitingAndHTTPError(t *testing.T) {
	old := localAIHTTP
	defer func() { localAIHTTP = old }()
	calls := 0
	localAIHTTP = &http.Client{Transport: aiRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("untrusted model body")), Header: http.Header{}}, nil
	})}
	localInferenceSlot <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := generateLocalDiagnosisContext(ctx, Event{}, "qwen3:4b-instruct")
	<-localInferenceSlot
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("cancelled wait sent inference", err, calls)
	}
	_, err = generateLocalDiagnosis(Event{}, "qwen3:4b-instruct")
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") || strings.Contains(err.Error(), "untrusted") || len(localInferenceSlot) != 0 {
		t.Fatal("HTTP failure missing or body disclosed or slot leaked", err)
	}
}
