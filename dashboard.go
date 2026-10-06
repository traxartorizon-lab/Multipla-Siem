package main

import (
	"errors"
	"net/http"
	"strings"
)

var dashboardCards = []string{"collection", "alerts", "devices", "response", "activity", "posture", "recent-alerts"}

func validateDashboardOrder(order []string) error {
	if len(order) > len(dashboardCards) {
		return errors.New("disposição inválida")
	}
	seen := map[string]bool{}
	for _, id := range order {
		valid := false
		for _, known := range dashboardCards {
			if known == id {
				valid = true
				break
			}
		}
		if !valid || seen[id] {
			return errors.New("card desconhecido ou repetido")
		}
		seen[id] = true
	}
	return nil
}

func (a *App) registerDashboardRoutes(mux *http.ServeMux) {
	mux.HandleFunc("PUT /api/dashboard/layout", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Order []string `json:"order"`
		}
		if !decode(w, r, &body) {
			return
		}
		if err := validateDashboardOrder(body.Order); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		session, _ := a.session(r)
		email := strings.ToLower(session.Email)
		a.mu.Lock()
		defer a.mu.Unlock()
		old, existed := a.state.Preferences[email]
		if a.state.Preferences == nil {
			a.state.Preferences = map[string]Preferences{}
		}
		if !existed && len(a.state.Preferences) >= 102 {
			http.Error(w, "limite de contas", 400)
			return
		}
		p := a.preferences(email)
		p.DashboardOrder = append([]string(nil), body.Order...)
		a.state.Preferences[email] = p
		if err := a.persist(); err != nil {
			if existed {
				a.state.Preferences[email] = old
			} else {
				delete(a.state.Preferences, email)
			}
			http.Error(w, "falha ao salvar disposição", 500)
			return
		}
		writeJSON(w, map[string]any{"order": p.DashboardOrder})
	}))
}
