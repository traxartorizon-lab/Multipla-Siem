package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

// One-time migration after a validated response, limited to the two replaced models.
// No custom model or active selection is removed; Ollama manages shared blobs itself.
func (a *App) cleanupLegacyOllamaModels(validatedModel string) {
	a.mu.Lock()
	if a.demo || validatedModel != "qwen3:4b-instruct" || a.localAISnapshot().Model != validatedModel || a.state.OllamaLegacyCleaned || a.aiCleanupRunning {
		a.mu.Unlock()
		return
	}
	a.aiCleanupRunning = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.aiCleanupRunning = false; a.aiCleanupTarget = ""; a.mu.Unlock() }()
	models, err := readLocalAIModels()
	if err != nil {
		return
	}
	installed := map[string]bool{}
	for _, m := range models {
		installed[m] = true
	}
	client := *localAIHTTP
	client.Timeout = 10 * time.Second
	for _, name := range []string{"qwen3:0.6b", "qwen3:4b"} {
		if !installed[name] {
			continue
		}
		a.mu.Lock()
		if a.localAISnapshot().Model != validatedModel {
			a.mu.Unlock()
			return
		}
		a.aiCleanupTarget = name
		a.mu.Unlock()
		body, _ := json.Marshal(map[string]string{"model": name})
		request, _ := http.NewRequest("DELETE", localAIURL+"/api/delete", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			return
		}
		response.Body.Close()
		if response.StatusCode != 200 && response.StatusCode != 404 {
			return
		}
		a.mu.Lock()
		remaining := []string{}
		for _, m := range a.aiStatus.Models {
			if m != name {
				remaining = append(remaining, m)
			}
		}
		a.aiStatus.Models = remaining
		a.audit("system", "Modelo Ollama substituído removido: "+name)
		a.mu.Unlock()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.OllamaLegacyCleaned = true
	if a.persist() != nil {
		a.state.OllamaLegacyCleaned = false
	}
}
