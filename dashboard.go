package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

var dashboardCards = []string{"collection", "alerts", "devices", "response", "resources", "activity", "recent-alerts", "posture"}

func validateDashboardOrder(order []string) error {
	if len(order) > len(dashboardCards)+7 {
		return errors.New("disposição inválida")
	}
	seen := map[string]bool{}
	for _, id := range order {
		valid := validExtraResourceID(id)
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
			Order []string                         `json:"order"`
			Cards map[string]DashboardCardSettings `json:"cards"`
		}
		if !decode(w, r, &body) {
			return
		}
		if err := validateDashboardOrder(body.Order); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := validateDashboardSettings(body.Cards); err != nil {
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
		if body.Cards != nil {
			p.DashboardCards = body.Cards
		}
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

func validExtraResourceID(id string) bool {
	if !strings.HasPrefix(id, "resources-") {
		return false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(id, "resources-"))
	return err == nil && n >= 2 && n <= 8 && id == "resources-"+strconv.Itoa(n)
}
func validateDashboardSettings(cards map[string]DashboardCardSettings) error {
	if len(cards) > 15 {
		return errors.New("limite de cards")
	}
	for id, c := range cards {
		if err := validateDashboardOrder([]string{id}); err != nil {
			return err
		}
		if c.Width < 0 || c.Width > 4 || c.Height < 0 || c.Height > 1200 || (c.Height > 0 && c.Height < 120) || len(c.Device) > 64 {
			return errors.New("dimensões inválidas")
		}
		if c.Device != "" && id != "resources" && !validExtraResourceID(id) {
			return errors.New("máquina somente em card de recursos")
		}
	}
	return nil
}
