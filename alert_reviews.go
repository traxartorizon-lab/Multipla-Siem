package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type AlertReview struct {
	Title   string    `json:"title"`
	Level   int       `json:"level"`
	Status  string    `json:"status"`
	Notes   string    `json:"notes"`
	Updated time.Time `json:"updated"`
	Actor   string    `json:"actor"`
}

func (a *App) registerAlertRoutes(mux *http.ServeMux) {
	mux.HandleFunc("PUT /api/alerts/{id}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var value AlertReview
		if !decode(w, r, &value) {
			return
		}
		value.Title = strings.TrimSpace(value.Title)
		value.Notes = strings.TrimSpace(value.Notes)
		if len(value.Title) > 200 || len(value.Notes) > 2000 || value.Level < 1 || value.Level > 15 || (value.Status != "open" && value.Status != "investigating" && value.Status != "resolved" && value.Status != "false_positive") {
			http.Error(w, "Titulo, nivel, estado ou observacoes invalidos", 400)
			return
		}
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		id := r.PathValue("id")
		found := false
		for _, event := range a.events {
			if event.ID == id {
				found = true
				break
			}
		}
		if !found {
			history, _, _, err := a.historyEvents(r, 0, id)
			if err == nil && len(history) == 1 {
				found = true
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		if a.state.AlertReviews == nil {
			a.state.AlertReviews = map[string]AlertReview{}
		}
		previous, existed := a.state.AlertReviews[id]
		if !existed && len(a.state.AlertReviews) >= 2000 {
			http.Error(w, "Limite de acompanhamentos atingido", 409)
			return
		}
		value.Title = redact(value.Title)
		value.Notes = redact(value.Notes)
		value.Actor = redact(s.Email)
		value.Updated = time.Now().UTC()
		if encoded, _ := json.Marshal(value); len(encoded) > 2048 {
			http.Error(w, "Avaliação muito extensa; reduza as observações", 400)
			return
		}
		oldAudit := append([]Audit{}, a.state.Audit...)
		a.state.AlertReviews[id] = value
		a.audit(s.Email, "acompanhamento de alerta atualizado: "+id)
		if err := a.persist(); err != nil {
			if existed {
				a.state.AlertReviews[id] = previous
			} else {
				delete(a.state.AlertReviews, id)
			}
			a.state.Audit = oldAudit
			http.Error(w, "Falha ao salvar acompanhamento", 500)
			return
		}
		if value.Level >= 12 && value.Status != "false_positive" {
			for _, event := range a.events {
				if event.ID == id {
					event.Level = value.Level
					event.Diagnosis = localDiagnosis(event)
					a.enqueueLocalAI(event)
					break
				}
			}
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
