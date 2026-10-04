package main

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

type LocalAdmin struct {
	Email string `json:"email"`
	Salt  string `json:"salt"`
	Hash  string `json:"password_hash"`
}

var passwordSlots = make(chan struct{}, 2)

func passwordHash(password, salt string) (string, error) {
	select {
	case passwordSlots <- struct{}{}:
		defer func() { <-passwordSlots }()
	default:
		return "", fmt.Errorf("verificação ocupada; tente novamente")
	}
	derived, err := pbkdf2.Key(sha256.New, password, []byte(salt), 600000, 32)
	return base64.RawURLEncoding.EncodeToString(derived), err
}

func (a *App) registerLocalAuth(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/options", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		writeJSON(w, map[string]bool{"local_ready": a.state.LocalAdmin.Hash != "", "google_ready": a.state.GoogleSettings != "" || (secret("GOOGLE_CLIENT_ID") != "" && secret("GOOGLE_CLIENT_SECRET") != "")})
	})
	mux.HandleFunc("POST /auth/password", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != a.origin {
			http.Error(w, "origem inválida", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if r.ParseForm() != nil {
			http.Error(w, "formulário inválido", 400)
			return
		}
		password := r.FormValue("password")
		if len(password) > 256 {
			http.Error(w, "Credenciais inválidas", 403)
			return
		}
		a.mu.Lock()
		admin := a.state.LocalAdmin
		a.mu.Unlock()
		salt := admin.Salt
		if salt == "" {
			salt = "unconfigured-local-account"
		}
		hash, err := passwordHash(password, salt)
		if err != nil || admin.Hash == "" || !equal(hash, admin.Hash) || !strings.EqualFold(r.FormValue("email"), admin.Email) {
			http.Error(w, "Credenciais inválidas", 403)
			return
		}
		a.newSession(w, r, admin.Email)
	})
	mux.HandleFunc("POST /api/account/local", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if !decode(w, r, &input) {
			return
		}
		s, _ := a.session(r)
		input.Email = strings.ToLower(strings.TrimSpace(input.Email))
		if len(input.Password) < 14 || len(input.Password) > 256 || len(input.Email) > 254 || !strings.Contains(input.Email, "@") || strings.ContainsAny(input.Email, "\r\n\x00 ") {
			http.Error(w, "Informe email válido e senha de 14 a 256 caracteres", 400)
			return
		}
		salt := token()
		hash, err := passwordHash(input.Password, salt)
		if err != nil {
			http.Error(w, "falha na criação", 500)
			return
		}
		a.mu.Lock()
		if a.state.LocalAdmin.Hash != "" || s.Email != "bootstrap" {
			a.mu.Unlock()
			http.Error(w, "Conta já cadastrada ou acesso não autorizado", 403)
			return
		}
		allowed := false
		for _, email := range a.cfg.AllowedEmails {
			if strings.EqualFold(email, input.Email) {
				allowed = true
			}
		}
		oldConfig := a.cfg
		if !allowed {
			a.cfg.AllowedEmails = append(append([]string(nil), a.cfg.AllowedEmails...), input.Email)
		}
		if err = validateConfig(a.cfg); err != nil {
			a.cfg = oldConfig
			a.mu.Unlock()
			http.Error(w, "configuração inválida", 400)
			return
		}
		if err = atomicJSON(a.configPath, a.cfg); err != nil {
			a.cfg = oldConfig
			a.mu.Unlock()
			http.Error(w, "falha na configuração", 503)
			return
		}
		old := a.state.LocalAdmin
		a.state.LocalAdmin = LocalAdmin{Email: input.Email, Salt: salt, Hash: hash}
		a.audit(input.Email, "conta administrativa local cadastrada")
		if err = a.persist(); err != nil {
			a.state.LocalAdmin = old
			a.cfg = oldConfig
			atomicJSON(a.configPath, oldConfig)
			a.mu.Unlock()
			http.Error(w, "falha ao salvar conta", 503)
			return
		}
		for id, session := range a.sessions {
			if session.Email == "bootstrap" {
				delete(a.sessions, id)
				delete(a.active, id)
			}
		}
		a.mu.Unlock()
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
