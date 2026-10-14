package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
)

type DesktopLogin struct {
	Challenge, Email, Subject, AccountDigest, Consent string
	Expires                                           time.Time
	Approved                                          bool
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func loginChallengeValid(value string) bool {
	b, e := base64.RawURLEncoding.DecodeString(value)
	return e == nil && len(b) == 32 && len(value) == 43
}
func desktopLoginCode(id string) string {
	h := secretDigest(id)
	return strings.ToUpper(h[:4] + "-" + h[4:8])
}
func (a *App) desktopLoginAllowedLocked(email string) bool {
	if a.roleLocked(email) == "disabled" {
		return false
	}
	for _, e := range a.cfg.AllowedEmails {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	return false
}
func (a *App) desktopLoginConsent(w http.ResponseWriter, r *http.Request, id, email, subject string) {
	a.mu.Lock()
	flow, ok := a.desktopLogins[id]
	if !ok || !time.Now().Before(flow.Expires) || flow.Email != "" || !a.desktopLoginAllowedLocked(email) {
		a.mu.Unlock()
		http.Error(w, "Vinculação expirada ou não autorizada", 403)
		return
	}
	flow.Email = strings.ToLower(email)
	flow.Subject = subject
	flow.AccountDigest = a.desktopAccountDigest(flow.Email)
	flow.Consent = token()
	a.desktopLogins[id] = flow
	a.mu.Unlock()
	a.cookie(w, "__Host-multipla_desktop_consent", flow.Consent, 300)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	fmt.Fprintf(w, `<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Autorizar aplicativo Multipla SIEM</title><h1>Autorizar login no aplicativo Windows</h1><p>Conta: <strong>%s</strong></p><p>Confira se o aplicativo que você abriu mostra exatamente este código: <strong>%s</strong>.</p><p>Não confirme solicitações que você não iniciou. Esta autorização abre uma sessão com as permissões desta conta no aplicativo.</p><form method="post" action="/auth/desktop/approve"><input type="hidden" name="id" value="%s"><input type="hidden" name="consent" value="%s"><button>Confirmar login no meu aplicativo</button></form><p>Para cancelar, feche esta página. A solicitação expira em cinco minutos.</p></html>`, html.EscapeString(flow.Email), desktopLoginCode(id), html.EscapeString(id), html.EscapeString(flow.Consent))
}
func (a *App) registerDesktopLoginRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/desktop/start", func(w http.ResponseWriter, r *http.Request) {
		if a.demo || r.TLS == nil || a.googleSecret("GOOGLE_CLIENT_ID") == "" || a.googleSecret("GOOGLE_CLIENT_SECRET") == "" {
			http.Error(w, "Google/HTTPS indisponível", 503)
			return
		}
		var input struct {
			Challenge string `json:"challenge"`
		}
		if !decode(w, r, &input) {
			return
		}
		if !loginChallengeValid(input.Challenge) {
			http.Error(w, "PKCE inválido", 400)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.desktopLogins == nil {
			a.desktopLogins = map[string]DesktopLogin{}
		}
		for id, f := range a.desktopLogins {
			if !time.Now().Before(f.Expires) {
				delete(a.desktopLogins, id)
			}
		}
		if len(a.desktopLogins) >= 100 {
			http.Error(w, "Limite de autenticações", 429)
			return
		}
		id := token()
		a.desktopLogins[id] = DesktopLogin{Challenge: input.Challenge, Expires: time.Now().Add(5 * time.Minute)}
		writeJSON(w, map[string]string{"id": id, "code": desktopLoginCode(id), "url": a.origin + "/auth/desktop/google?id=" + id})
	})
	mux.HandleFunc("GET /auth/desktop/google", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || a.demo {
			http.Error(w, "HTTPS obrigatório", 403)
			return
		}
		id := r.URL.Query().Get("id")
		a.mu.Lock()
		flow, ok := a.desktopLogins[id]
		a.mu.Unlock()
		if !ok || !time.Now().Before(flow.Expires) || flow.Email != "" {
			http.Error(w, "Solicitação expirada", 403)
			return
		}
		a.oauthStart(w, r)
	})
	mux.HandleFunc("POST /auth/desktop/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.Header.Get("Origin") != a.origin {
			http.Error(w, "Origem inválida", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if r.ParseForm() != nil {
			http.Error(w, "Formulário inválido", 400)
			return
		}
		consent, ok := a.cookieValue(r, "__Host-multipla_desktop_consent")
		a.mu.Lock()
		defer a.mu.Unlock()
		id := r.FormValue("id")
		flow, exists := a.desktopLogins[id]
		if !ok || !exists || !equal(consent, flow.Consent) || !equal(consent, r.FormValue("consent")) || flow.Approved || !time.Now().Before(flow.Expires) || !a.desktopLoginAllowedLocked(flow.Email) || !equal(flow.AccountDigest, a.desktopAccountDigest(flow.Email)) {
			http.Error(w, "Consentimento inválido ou expirado", 403)
			return
		}
		flow.Approved = true
		flow.Consent = ""
		a.desktopLogins[id] = flow
		a.cookie(w, "__Host-multipla_desktop_consent", "", -1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><html lang=pt-BR><meta charset=utf-8><title>Login autorizado</title><h1>Login autorizado</h1><p>Volte ao aplicativo e confira a conta antes de continuar. Você pode fechar esta página.</p></html>")
	})
	mux.HandleFunc("POST /auth/desktop/status", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "HTTPS obrigatório", 403)
			return
		}
		var input struct {
			ID       string `json:"id"`
			Verifier string `json:"verifier"`
		}
		if !decode(w, r, &input) {
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		flow, ok := a.desktopLogins[input.ID]
		if !ok || !time.Now().Before(flow.Expires) || !loginChallengeValid(input.Verifier) || !equal(flow.Challenge, pkceChallenge(input.Verifier)) {
			http.Error(w, "Solicitação inválida ou expirada", 403)
			return
		}
		writeJSON(w, map[string]any{"approved": flow.Approved, "email": flow.Email})
	})
	mux.HandleFunc("POST /auth/desktop/consume", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "HTTPS obrigatório", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if r.ParseForm() != nil {
			http.Error(w, "Formulário inválido", 400)
			return
		}
		id, verifier := r.FormValue("id"), r.FormValue("verifier")
		a.mu.Lock()
		flow, ok := a.desktopLogins[id]
		if !ok || !flow.Approved || !time.Now().Before(flow.Expires) || !loginChallengeValid(verifier) || !equal(flow.Challenge, pkceChallenge(verifier)) || !a.desktopLoginAllowedLocked(flow.Email) || !equal(flow.AccountDigest, a.desktopAccountDigest(flow.Email)) {
			a.mu.Unlock()
			http.Error(w, "Autorização inválida ou expirada", 403)
			return
		}
		delete(a.desktopLogins, id)
		a.mu.Unlock()
		// Create the normal HttpOnly session directly in the isolated WebView profile.
		// Neither Google tokens nor browser cookies are copied into the native client.
		a.newSession(w, r, flow.Email, flow.Subject)
	})
}
