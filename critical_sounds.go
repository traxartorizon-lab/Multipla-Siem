package main

import (
	"net/http"
	"sort"
	"time"
)

func validCriticalSound(value string) bool { return value == "" || value == "beep" || value == "siren" }

// Empty sound type preserves the browser's default for existing backups.
func (a *App) registerCriticalSoundRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/critical-sounds", a.auth(func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Key string `json:"key"`
			CriticalPattern
		}
		a.mu.Lock()
		rows := []row{}
		for key, policy := range a.state.CriticalPatterns {
			if policy.Critical {
				rows = append(rows, row{key, policy})
			}
		}
		a.mu.Unlock()
		sort.Slice(rows, func(i, j int) bool { return rows[i].Updated.After(rows[j].Updated) })
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, rows)
	}))
	change := func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Sound     bool   `json:"sound"`
			SoundType string `json:"sound_type"`
		}
		deleting := r.Method == http.MethodDelete
		if !deleting && !decode(w, r, &input) {
			return
		}
		if !validCriticalSound(input.SoundType) {
			http.Error(w, "Som inválido", 400)
			return
		}
		session, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		key := r.PathValue("key")
		previous, ok := a.state.CriticalPatterns[key]
		if !ok || !previous.Critical {
			http.NotFound(w, r)
			return
		}
		policy := previous
		policy.Sound = input.Sound
		policy.SoundType = input.SoundType
		// Keep the explicit exclusion so built-in detectors do not recreate this alert.
		if deleting {
			policy.Critical = false
			policy.Sound = false
		}
		policy.Updated = time.Now().UTC()
		oldAudit := append([]Audit{}, a.state.Audit...)
		a.state.CriticalPatterns[key] = policy
		action := "áudio da descrição atualizado: "
		if deleting {
			action = "alerta por descrição excluído (evidência preservada): "
		}
		a.audit(session.Email, action+key+"; som="+boolText(policy.Sound)+"; tipo="+policy.SoundType)
		if err := a.persist(); err != nil {
			a.state.CriticalPatterns[key] = previous
			a.state.Audit = oldAudit
			http.Error(w, "Falha ao salvar alerta", 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}
	mux.HandleFunc("PUT /api/critical-sounds/{key}", a.auth(change))
	mux.HandleFunc("DELETE /api/critical-sounds/{key}", a.auth(change))
}
