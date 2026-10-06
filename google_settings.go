package main

import (
	"net/http"
	"strings"
	"sync/atomic"
)

var googleRedaction atomic.Pointer[string]

func (a *App) googleSecret(name string) string {
	a.mu.Lock()
	encoded := a.state.GoogleSettings
	a.mu.Unlock()
	if encoded != "" {
		if value, err := openDriveToken("multipla-oauth-config", encoded); err == nil {
			if name == "GOOGLE_CLIENT_ID" {
				return value.Access
			}
			return value.Refresh
		}
		return ""
	}
	return secret(name)
}

func (a *App) registerGoogleSettings(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/settings/google", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		if !decode(w, r, &input) {
			return
		}
		if len(input.ClientID) > 512 || !strings.HasSuffix(input.ClientID, ".apps.googleusercontent.com") || len(input.ClientSecret) < 8 || len(input.ClientSecret) > 4096 || strings.ContainsAny(input.ClientSecret, "\r\n\x00") {
			http.Error(w, "Credenciais OAuth inválidas", 400)
			return
		}
		encrypted, err := sealDriveToken("multipla-oauth-config", DriveToken{Access: input.ClientID, Refresh: input.ClientSecret})
		if err != nil {
			http.Error(w, "Chave de proteção ausente; atualize pelo instalador do pacote", 503)
			return
		}
		a.driveMu.Lock()
		defer a.driveMu.Unlock()
		a.mu.Lock()
		defer a.mu.Unlock()
		oldSettings, oldTokens := a.state.GoogleSettings, a.state.DriveTokens
		a.state.GoogleSettings = encrypted
		a.state.DriveTokens = map[string]string{}
		if err = a.persist(); err != nil {
			a.state.GoogleSettings = oldSettings
			a.state.DriveTokens = oldTokens
			http.Error(w, "falha ao salvar", 503)
			return
		}
		googleRedaction.Store(&input.ClientSecret)
		a.oauth = map[string]OAuth{}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
