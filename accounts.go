package main

import (
	"net/http"
	"net/mail"
	"strings"
)

type AccessAccount struct {
	Role     string `json:"role"`
	Salt     string `json:"salt,omitempty"`
	Hash     string `json:"password_hash,omitempty"`
	Disabled bool   `json:"disabled"`
}

func (a *App) roleLocked(email string) string {
	if account, ok := a.state.Accounts[strings.ToLower(email)]; ok {
		if account.Disabled {
			return "disabled"
		}
		if account.Role == "admin" {
			return "admin"
		}
		return "viewer"
	}
	return "admin" // Existing authorized accounts keep their original access.
}

func (a *App) registerAccountRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/accounts", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		rows := []map[string]any{}
		for _, email := range a.cfg.AllowedEmails {
			account := a.state.Accounts[strings.ToLower(email)]
			rows = append(rows, map[string]any{"email": email, "role": a.roleLocked(email), "disabled": account.Disabled, "local_login": account.Hash != "" || strings.EqualFold(email, a.state.LocalAdmin.Email), "primary": strings.EqualFold(email, a.state.LocalAdmin.Email)})
		}
		writeJSON(w, map[string]any{"accounts": rows})
	}))
	mux.HandleFunc("PUT /api/accounts", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Email    string `json:"email"`
			Role     string `json:"role"`
			Password string `json:"password"`
			Disabled bool   `json:"disabled"`
		}
		if !decode(w, r, &input) {
			return
		}
		input.Email = strings.ToLower(strings.TrimSpace(input.Email))
		address, err := mail.ParseAddress(input.Email)
		if err != nil || address.Address != input.Email || len(input.Email) > 254 || (input.Role != "admin" && input.Role != "viewer") || (input.Password != "" && (len(input.Password) < 14 || len(input.Password) > 256)) {
			http.Error(w, "Email, perfil ou senha invalidos; senha deve ter 14 a 256 caracteres", 400)
			return
		}
		var salt, hash string
		if input.Password != "" {
			salt = token()
			hash, err = passwordHash(input.Password, salt)
			if err != nil {
				http.Error(w, "Verificacao ocupada; tente novamente", 503)
				return
			}
		}
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		if strings.EqualFold(input.Email, a.state.LocalAdmin.Email) {
			http.Error(w, "A conta administrativa principal permanece protegida", 400)
			return
		}
		accounts := map[string]AccessAccount{}
		for k, v := range a.state.Accounts {
			accounts[k] = v
		}
		previous := accounts[input.Email]
		if input.Password == "" {
			salt, hash = previous.Salt, previous.Hash
		}
		accounts[input.Email] = AccessAccount{Role: input.Role, Salt: salt, Hash: hash, Disabled: input.Disabled}
		if len(accounts) > 100 {
			http.Error(w, "Limite de contas atingido", 400)
			return
		}
		cfg := a.cfg
		cfg.AllowedEmails = append([]string{}, cfg.AllowedEmails...)
		exists := false
		for _, email := range cfg.AllowedEmails {
			if strings.EqualFold(email, input.Email) {
				exists = true
			}
		}
		if !exists {
			cfg.AllowedEmails = append(cfg.AllowedEmails, input.Email)
		}
		if validateConfig(cfg) != nil {
			http.Error(w, "Configuracao de contas invalida", 400)
			return
		}
		oldAccounts, oldAudit := a.state.Accounts, append([]Audit{}, a.state.Audit...)
		// Persist the explicit role before granting an email access. A crash
		// between writes must never turn a new viewer into a legacy admin.
		a.state.Accounts = accounts
		a.audit(s.Email, "conta de acesso atualizada: "+input.Email+" perfil "+input.Role)
		if a.persist() != nil {
			a.state.Accounts = oldAccounts
			a.state.Audit = oldAudit
			http.Error(w, "Falha ao salvar conta", 503)
			return
		}
		if atomicJSON(a.configPath, cfg) != nil {
			a.state.Accounts = oldAccounts
			a.state.Audit = oldAudit
			if a.persist() != nil {
				a.storageError = "Falha ao desfazer cadastro; revise contas antes de liberar novos acessos"
			}
			http.Error(w, "Falha ao salvar configuracao", 503)
			return
		}
		a.cfg = cfg
		for id, session := range a.sessions {
			if strings.EqualFold(session.Email, input.Email) {
				delete(a.sessions, id)
				delete(a.active, id)
			}
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
