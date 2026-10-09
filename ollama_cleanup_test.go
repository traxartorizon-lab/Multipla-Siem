package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestOllamaCleanupPreservesSelectedAndCustomModels(t *testing.T) {
	old := localAIHTTP
	defer func() { localAIHTTP = old }()
	deleted := []string{}
	localAIHTTP = &http.Client{Transport: aiRoundTripper(func(r *http.Request) (*http.Response, error) {
		body := `{"models":[{"name":"qwen3:4b-instruct","size":1,"details":{"format":"gguf"}},{"name":"qwen3:4b","size":1,"details":{"format":"gguf"}},{"name":"qwen3:0.6b","size":1,"details":{"format":"gguf"}},{"name":"custom:latest","size":1,"details":{"format":"gguf"}}]}`
		if r.Method == "DELETE" {
			var p struct {
				Model string `json:"model"`
			}
			json.NewDecoder(r.Body).Decode(&p)
			deleted = append(deleted, p.Model)
			body = `{}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	a := testApp(t)
	a.demo = false
	a.state.LocalAIModel = "qwen3:4b-instruct"
	a.cleanupLegacyOllamaModels("qwen3:4b")
	if len(deleted) != 0 {
		t.Fatal("unvalidated replacement caused deletion")
	}
	a.cleanupLegacyOllamaModels("qwen3:4b-instruct")
	if len(deleted) != 2 || deleted[0] != "qwen3:0.6b" || deleted[1] != "qwen3:4b" || !a.state.OllamaLegacyCleaned {
		t.Fatalf("incorrect cleanup: %v", deleted)
	}
	a.cleanupLegacyOllamaModels("qwen3:4b-instruct")
	if len(deleted) != 2 {
		t.Fatal("migration repeated")
	}
}
