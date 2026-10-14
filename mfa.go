package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

type MFARecord struct {
	EncryptedSecret string `json:"encrypted_secret"`
	LastStep        int64  `json:"last_step"`
}
type MFAEnrollment struct {
	Secret  string
	Session string
	Email   string
	Expires time.Time
	QR      []byte // Session-only image; never persisted or generated on repeated GETs.
}

func mfaURI(email, secret string) string {
	return "otpauth://totp/" + url.PathEscape("Multipla SIEM:"+email) + "?secret=" + secret + "&issuer=Multipla%20SIEM&algorithm=SHA1&digits=6&period=30"
}

func (a *App) mfaRequired() bool {
	if a.demo {
		return false
	}
	if a.cfg.RequireMFA != nil {
		return *a.cfg.RequireMFA
	}
	return strings.HasPrefix(a.cfg.PublicURL, "https://")
}
func totp(secret string, step int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) < 20 {
		return ""
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	off := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}
func sealMFA(email, secret string) (string, error) {
	g, err := driveCipher()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(secret), []byte("mfa/v1/"+strings.ToLower(email)))), nil
}
func openMFA(email, encrypted string) (string, error) {
	g, err := driveCipher()
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil || len(raw) < g.NonceSize() {
		return "", fmt.Errorf("credencial MFA inválida")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte("mfa/v1/"+strings.ToLower(email)))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
func verifyTOTP(secret, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	step := now.Unix() / 30
	for _, delta := range []int64{0, -1, 1} {
		n := step + delta
		if n > last && subtle.ConstantTimeCompare([]byte(totp(secret, n)), []byte(code)) == 1 {
			return n, true
		}
	}
	return 0, false
}

// First factor sessions are limited to MFA setup/verification until a valid second factor.
func (a *App) mfaSession(r *http.Request) (string, Session, bool) {
	id, ok := a.cookieValue(r, a.sessionName())
	if !ok {
		return "", Session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[id]
	if !ok || !time.Now().Before(s.Expires) || a.roleLocked(s.Email) == "disabled" || s.Email == "bootstrap" {
		return "", Session{}, false
	}
	allowed := false
	for _, email := range a.cfg.AllowedEmails {
		if strings.EqualFold(email, s.Email) {
			allowed = true
		}
	}
	if !allowed {
		return "", Session{}, false
	}
	if s.MFATime.IsZero() && time.Since(s.Created) > 5*time.Minute {
		return "", Session{}, false
	}
	if last := a.active[id]; !s.MFATime.IsZero() && !last.IsZero() && time.Since(last) > 15*time.Minute {
		return "", Session{}, false
	}
	return id, s, true
}
func sensitiveOperation(method, path string) bool {
	if method == "GET" {
		return false
	}
	for _, prefix := range []string{"/api/isolation/release", "/api/config", "/api/rules", "/api/block", "/api/account/local", "/api/accounts", "/api/settings/google", "/api/system/reboot", "/api/system/update", "/api/backup/import", "/api/backups/", "/api/ssh/sessions", "/api/drive/backups/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
func (a *App) registerMFARoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/mfa", func(w http.ResponseWriter, r *http.Request) {
		_, s, ok := a.mfaSession(r)
		if !ok {
			http.Redirect(w, r, "/", 303)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verificação MFA · Multipla SIEM</title><link rel="stylesheet" href="/mfa.css"><script src="/mfa.js" defer></script></head><body><main><h1>Proteja seu acesso</h1><p>Use seu aplicativo autenticador. O mesmo segundo fator é exigido nos acessos Google e locais.</p><p id="mfa-account"></p><section id="mfa-enrollment" hidden><h2>Configurar autenticador</h2><p>No Authy, adicione uma conta e escaneie este QR code. Depois informe abaixo o código de seis dígitos exibido pelo aplicativo.</p><img id="mfa-qr" width="300" height="300" alt="QR code para cadastrar Multipla SIEM no autenticador"><p id="mfa-expiry"></p><details><summary>Não consigo escanear: usar chave manual</summary><p>TOTP: SHA-1, seis dígitos, intervalo de 30 segundos.</p><label>Chave de configuração<input id="mfa-secret" readonly autocomplete="off"></label><a id="mfa-uri">Abrir no autenticador deste dispositivo</a></details><p>Guarde o autenticador com segurança. Não envie esta chave em prints. A chave não permite entrar sem sua conta/senha.</p></section><form id="mfa-form"><label>Código de seis dígitos<input name="code" required pattern="[0-9]{6}" maxlength="12" inputmode="numeric" autocomplete="one-time-code"></label><button disabled>Verificar e entrar</button></form><p id="mfa-status" role="status"></p><a href="/">Voltar ao login</a></main></body></html>`))
		_ = s
	})
	mux.HandleFunc("GET /auth/mfa/status", func(w http.ResponseWriter, r *http.Request) {
		_, s, ok := a.mfaSession(r)
		if !ok {
			http.Error(w, "Entre novamente", 401)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		writeJSON(w, map[string]any{"email": s.Email, "csrf": s.CSRF, "enrolled": a.state.MFA[strings.ToLower(s.Email)].EncryptedSecret != ""})
	})
	mux.HandleFunc("POST /auth/mfa/enroll", func(w http.ResponseWriter, r *http.Request) {
		id, s, ok := a.mfaSession(r)
		if !ok {
			http.Error(w, "Sessão de cadastro expirada. Volte ao login e entre novamente.", 401)
			return
		}
		if r.Header.Get("Origin") != a.origin || !equal(r.Header.Get("X-CSRF-Token"), s.CSRF) {
			http.Error(w, "Solicitação inválida", 403)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		email := strings.ToLower(s.Email)
		if a.state.MFA[email].EncryptedSecret != "" {
			http.Error(w, "MFA já configurado", 409)
			return
		}
		if _, err := driveCipher(); err != nil {
			http.Error(w, "Criptografia MFA indisponível; administrador deve validar a chave de criptografia no servidor", 503)
			return
		}
		if a.mfaEnrollments == nil {
			a.mfaEnrollments = map[string]MFAEnrollment{}
		}
		if pending, exists := a.mfaEnrollments[id]; exists && pending.Email == email && time.Now().Before(pending.Expires) {
			writeJSON(w, map[string]string{"secret": pending.Secret, "uri": mfaURI(email, pending.Secret), "qr": "/auth/mfa/qr.png", "expires_at": pending.Expires.Format(time.RFC3339)})
			return
		}
		for owner, e := range a.mfaEnrollments {
			if !time.Now().Before(e.Expires) {
				delete(a.mfaEnrollments, owner)
			}
		}
		if len(a.mfaEnrollments) >= 100 {
			http.Error(w, "Limite de configurações", 429)
			return
		}
		raw := make([]byte, 20)
		if _, err := rand.Read(raw); err != nil {
			http.Error(w, "Falha de configuração", 503)
			return
		}
		secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		pending := MFAEnrollment{Secret: secret, Session: id, Email: email, Expires: s.Created.Add(5 * time.Minute)}
		pending.QR, _ = qrcode.Encode(mfaURI(email, secret), qrcode.Medium, -6)
		a.mfaEnrollments[id] = pending
		writeJSON(w, map[string]string{"secret": secret, "uri": mfaURI(email, secret), "qr": "/auth/mfa/qr.png", "expires_at": pending.Expires.Format(time.RFC3339)})
	})
	mux.HandleFunc("GET /auth/mfa/qr.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		id, s, ok := a.mfaSession(r)
		if !ok || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "Entre novamente", 403)
			return
		}
		a.mu.Lock()
		pending, exists := a.mfaEnrollments[id]
		enrolled := a.state.MFA[strings.ToLower(s.Email)].EncryptedSecret != ""
		a.mu.Unlock()
		if enrolled || !exists || pending.Session != id || pending.Email != strings.ToLower(s.Email) || !time.Now().Before(pending.Expires) {
			http.Error(w, "Configuração expirada; entre novamente", 409)
			return
		}
		if len(pending.QR) == 0 {
			http.Error(w, "QR indisponível; use a chave manual", 503)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(pending.QR)
	})
	verify := func(w http.ResponseWriter, r *http.Request) {
		id, s, ok := a.mfaSession(r)
		if !ok {
			http.Error(w, "Sessão expirada. Volte ao login e entre novamente.", 401)
			return
		}
		if r.Header.Get("Origin") != a.origin || !equal(r.Header.Get("X-CSRF-Token"), s.CSRF) {
			http.Error(w, "Solicitação inválida", 403)
			return
		}
		if !a.takeRate("mfa:"+strings.ToLower(s.Email), 5, time.Minute) {
			http.Error(w, "Limite de códigos; aguarde um minuto", 429)
			return
		}
		var input struct {
			Code string `json:"code"`
		}
		if !decode(w, r, &input) {
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		email := strings.ToLower(s.Email)
		record := a.state.MFA[email]
		secret := ""
		enrolling := record.EncryptedSecret == ""
		var err error
		if enrolling {
			pending, exists := a.mfaEnrollments[id]
			if !exists || pending.Session != id || pending.Email != email || !time.Now().Before(pending.Expires) {
				http.Error(w, "Configuração expirada; recarregue a página", 403)
				return
			}
			secret = pending.Secret
		} else {
			secret, err = openMFA(email, record.EncryptedSecret)
		}
		step, valid := verifyTOTP(secret, input.Code, time.Now(), record.LastStep)
		if err != nil || !valid {
			http.Error(w, "Código inválido, já utilizado ou relógio fora de sincronia. Aguarde um novo código.", 403)
			return
		}
		if enrolling {
			record.EncryptedSecret, err = sealMFA(email, secret)
			if err != nil {
				http.Error(w, "Falha ao proteger MFA", 503)
				return
			}
		}
		record.LastStep = step
		if a.state.MFA == nil {
			a.state.MFA = map[string]MFARecord{}
		}
		old := a.state.MFA[email]
		a.state.MFA[email] = record
		a.audit(email, "segundo fator validado")
		if a.persist() != nil {
			a.state.MFA[email] = old
			http.Error(w, "Auditoria indisponível; acesso não liberado", 503)
			return
		}
		for enrollmentID, pending := range a.mfaEnrollments {
			if pending.Email == email {
				delete(a.mfaEnrollments, enrollmentID)
			}
		}
		s.MFATime = time.Now().UTC()
		a.sessions[id] = s
		a.active[id] = time.Now()
		writeJSON(w, map[string]bool{"ok": true})
	}
	mux.HandleFunc("POST /auth/mfa/verify", verify)
	mux.HandleFunc("POST /auth/mfa/step-up", verify)
}
