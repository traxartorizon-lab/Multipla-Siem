package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type DesktopGrant struct {
	ID            string    `json:"id"`
	Owner         string    `json:"owner"`
	Name          string    `json:"name"`
	Digest        string    `json:"digest"`
	AccountDigest string    `json:"account_digest"`
	Expires       time.Time `json:"expires"`
}

func secretDigest(value string) string {
	d := sha256.Sum256([]byte(value))
	return hex.EncodeToString(d[:])
}
func (a *App) desktopAccountDigest(email string) string {
	account := a.state.Accounts[email]
	b, _ := json.Marshal([]any{account, a.groupLocked(email), a.state.LocalAdmin, a.state.GoogleSubjects[email], a.state.MFA[email].EncryptedSecret})
	return secretDigest(string(b))
}

func (a *App) desktopGrant(r *http.Request) (DesktopGrant, bool) {
	if a.demo || r.TLS == nil || len(r.Header.Values("Authorization")) != 1 {
		return DesktopGrant{}, false
	}
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return DesktopGrant{}, false
	}
	key := strings.TrimPrefix(value, "Bearer ")
	if len(key) != 43 {
		return DesktopGrant{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, grant := range a.state.DesktopGrants {
		if a.mfaRequired() && a.state.MFA[grant.Owner].EncryptedSecret == "" {
			continue
		}
		if !equal(secretDigest(key), grant.Digest) || !time.Now().Before(grant.Expires) || a.groupLocked(grant.Owner) == "disabled" || !equal(grant.AccountDigest, a.desktopAccountDigest(grant.Owner)) {
			continue
		}
		for _, email := range a.cfg.AllowedEmails {
			if strings.EqualFold(email, grant.Owner) {
				return grant, true
			}
		}
	}
	return DesktopGrant{}, false
}

func (a *App) registerDesktopRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/desktop/grants", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		rows := []map[string]any{}
		for _, g := range a.state.DesktopGrants {
			if g.Owner == strings.ToLower(s.Email) {
				rows = append(rows, map[string]any{"id": g.ID, "name": g.Name, "expires": g.Expires})
			}
		}
		writeJSON(w, map[string]any{"grants": rows})
	}))
	mux.HandleFunc("POST /api/desktop/grants", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || a.demo {
			http.Error(w, "Vinculação exige HTTPS em produção", 403)
			return
		}
		var input struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &input) {
			return
		}
		input.Name = strings.TrimSpace(input.Name)
		if len(input.Name) < 1 || len(input.Name) > 80 || strings.ContainsAny(input.Name, "\r\n\x00") {
			http.Error(w, "Nome inválido", 400)
			return
		}
		s, _ := a.session(r)
		owner := strings.ToLower(s.Email)
		key := token()
		a.mu.Lock()
		defer a.mu.Unlock()
		count := 0
		grants := map[string]DesktopGrant{}
		for id, g := range a.state.DesktopGrants {
			if time.Now().Before(g.Expires) {
				grants[id] = g
				if g.Owner == owner {
					count++
				}
			}
		}
		if count >= 5 || len(grants) >= 100 {
			http.Error(w, "Limite de apps vinculados; revogue um vínculo", 400)
			return
		}
		g := DesktopGrant{ID: token(), Owner: owner, Name: input.Name, Digest: secretDigest(key), AccountDigest: a.desktopAccountDigest(owner), Expires: time.Now().UTC().Add(7 * 24 * time.Hour)}
		grants[g.ID] = g
		old := a.state.DesktopGrants
		a.state.DesktopGrants = grants
		a.audit(owner, "app de notificações vinculado: "+g.ID)
		if a.persist() != nil {
			a.state.DesktopGrants = old
			http.Error(w, "Falha ao salvar vínculo", 503)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"id": g.ID, "key": key, "expires": g.Expires})
	}))
	mux.HandleFunc("DELETE /api/desktop/grants/{id}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		g, exists := a.state.DesktopGrants[r.PathValue("id")]
		if !exists || g.Owner != strings.ToLower(s.Email) {
			http.Error(w, "Vínculo não encontrado", 404)
			return
		}
		delete(a.state.DesktopGrants, g.ID)
		a.audit(s.Email, "vínculo do app revogado: "+g.ID)
		if a.persist() != nil {
			a.state.DesktopGrants[g.ID] = g
			http.Error(w, "Falha ao revogar", 503)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /api/desktop/notifications", func(w http.ResponseWriter, r *http.Request) {
		g, ok := a.desktopGrant(r)
		if !ok {
			http.Error(w, "Vínculo inválido ou expirado", 401)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		cleared := a.state.NotificationsCleared[g.Owner]
		all, _ := notificationView(a.state.Notifications, cleared)
		rows := []map[string]any{}
		scope := a.scopeLocked(g.Owner)
		for _, n := range all {
			if !scope.notification(n) {
				continue
			}
			n = a.notificationAudio(n)
			read := !n.Time.After(cleared) || a.state.NotificationReads[g.Owner][n.ID]
			rows = append(rows, map[string]any{"id": n.ID, "time": n.Time, "title": n.Title, "detail": n.Detail, "severity": n.Severity, "event_id": n.EventID, "read": read, "continuous": n.Continuous, "isolation_ip": n.IsolationIP, "sound": n.Sound, "sound_type": n.SoundType})
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"notifications": rows, "expires": g.Expires})
	})
	mux.HandleFunc("POST /api/desktop/notifications/read-all", func(w http.ResponseWriter, r *http.Request) {
		g, ok := a.desktopGrant(r)
		if !ok {
			http.Error(w, "Vínculo inválido ou expirado", 401)
			return
		}
		var input struct {
			IDs []string `json:"ids"`
		}
		if !decode(w, r, &input) {
			return
		}
		if len(input.IDs) > 200 {
			http.Error(w, "Limite de notificações", 400)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		valid := map[string]bool{}
		for _, n := range a.state.Notifications {
			if a.scopeLocked(g.Owner).notification(n) {
				valid[n.ID] = true
			}
		}
		if a.state.NotificationReads == nil {
			a.state.NotificationReads = map[string]map[string]bool{}
		}
		old := a.state.NotificationReads[g.Owner]
		next := map[string]bool{}
		for id, read := range old {
			if valid[id] {
				next[id] = read
			}
		}
		for _, id := range input.IDs {
			if valid[id] {
				next[id] = true
			}
		}
		a.state.NotificationReads[g.Owner] = next
		if a.persist() != nil {
			a.state.NotificationReads[g.Owner] = old
			http.Error(w, "Falha ao salvar leitura", 503)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/desktop/notifications/{id}/read", func(w http.ResponseWriter, r *http.Request) {
		g, ok := a.desktopGrant(r)
		if !ok {
			http.Error(w, "Vínculo inválido ou expirado", 401)
			return
		}
		a.markNotificationRead(w, r, g.Owner)
	})
	mux.HandleFunc("POST /api/notifications/{id}/read", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.markNotificationRead(w, r, strings.ToLower(s.Email))
	}))
}

func (a *App) markNotificationRead(w http.ResponseWriter, r *http.Request, owner string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := r.PathValue("id")
	exists := false
	valid := map[string]bool{}
	for _, n := range a.state.Notifications {
		valid[n.ID] = true
		if n.ID == id && a.scopeLocked(owner).notification(n) {
			exists = true
		}
	}
	if !exists {
		http.Error(w, "Notificação não encontrada", 404)
		return
	}
	if a.state.NotificationReads == nil {
		a.state.NotificationReads = map[string]map[string]bool{}
	}
	old := a.state.NotificationReads[owner]
	next := map[string]bool{}
	for k, v := range old {
		if valid[k] {
			next[k] = v
		}
	}
	next[id] = true
	a.state.NotificationReads[owner] = next
	if a.persist() != nil {
		a.state.NotificationReads[owner] = old
		http.Error(w, "Falha ao salvar leitura", 503)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
