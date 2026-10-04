package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const driveScope = "https://www.googleapis.com/auth/drive.file"

type DriveToken struct {
	Subject string    `json:"subject"`
	Access  string    `json:"access_token"`
	Refresh string    `json:"refresh_token"`
	Expires time.Time `json:"expires"`
	Scope   string    `json:"scope"`
}
type DriveFile struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Created    string            `json:"createdTime"`
	Properties map[string]string `json:"appProperties,omitempty"`
	Size       string            `json:"size,omitempty"`
	Mime       string            `json:"mimeType,omitempty"`
	Trashed    bool              `json:"trashed,omitempty"`
}

var driveID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,160}$`)

func driveCipher() (cipher.AEAD, error) {
	key, e := hex.DecodeString(secret("BACKUP_ENCRYPTION_KEY"))
	if e != nil || len(key) != 32 || !validLocalToken(secret("BACKUP_ENCRYPTION_KEY")) {
		return nil, errors.New("configure BACKUP_ENCRYPTION_KEY: execute novamente scripts/install.sh como root e reinicie o serviço")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func sealDriveToken(email string, t DriveToken) (string, error) {
	g, e := driveCipher()
	if e != nil {
		return "", e
	}
	plain, e := json.Marshal(t)
	if e != nil {
		return "", e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return "", e
	}
	out := g.Seal(nonce, nonce, plain, []byte(strings.ToLower(email)))
	return base64.RawURLEncoding.EncodeToString(out), nil
}
func openDriveToken(email, encoded string) (DriveToken, error) {
	var t DriveToken
	g, e := driveCipher()
	if e != nil {
		return t, e
	}
	data, e := base64.RawURLEncoding.DecodeString(encoded)
	if e != nil || len(data) < g.NonceSize() {
		return t, errors.New("reconecte o Google Drive")
	}
	plain, e := g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], []byte(strings.ToLower(email)))
	if e != nil || json.Unmarshal(plain, &t) != nil {
		return t, errors.New("credencial Drive inválida; reconecte a conta")
	}
	return t, nil
}
func (a *App) storeDriveToken(email string, t DriveToken) error {
	encrypted, e := sealDriveToken(email, t)
	if e != nil {
		return e
	}
	key := strings.ToLower(email)
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.state.DriveTokens[key]; !exists && len(a.state.DriveTokens) >= 102 {
		return errors.New("limite de contas Drive")
	}
	old := a.state.DriveTokens[key]
	a.state.DriveTokens[key] = encrypted
	if e = a.persist(); e != nil {
		if old == "" {
			delete(a.state.DriveTokens, key)
		} else {
			a.state.DriveTokens[key] = old
		}
		return errors.New("não foi possível salvar credencial Drive")
	}
	return nil
}
func (a *App) driveAccess(email string) (string, error) {
	a.mu.Lock()
	encoded := a.state.DriveTokens[strings.ToLower(email)]
	subject := a.state.GoogleSubjects[strings.ToLower(email)]
	allowed := false
	for _, v := range a.cfg.AllowedEmails {
		if strings.EqualFold(v, email) {
			allowed = true
		}
	}
	a.mu.Unlock()
	if a.demo || !allowed || encoded == "" {
		return "", errors.New("conecte o Drive com uma conta Google autorizada")
	}
	t, e := openDriveToken(email, encoded)
	if e != nil {
		return "", e
	}
	if subject == "" || t.Subject != subject {
		return "", errors.New("identidade Google mudou; reconecte o Drive")
	}
	if time.Now().Add(time.Minute).Before(t.Expires) {
		return t.Access, nil
	}
	resp, e := client.PostForm("https://oauth2.googleapis.com/token", url.Values{"client_id": {a.googleSecret("GOOGLE_CLIENT_ID")}, "client_secret": {a.googleSecret("GOOGLE_CLIENT_SECRET")}, "grant_type": {"refresh_token"}, "refresh_token": {t.Refresh}})
	if e != nil {
		return "", errors.New("Google indisponível; backup local permanece disponível")
	}
	defer resp.Body.Close()
	var v struct {
		Access  string `json:"access_token"`
		Expires int    `json:"expires_in"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&v) != nil || v.Access == "" || v.Expires <= 0 || v.Expires > 86400 {
		return "", errors.New("autorização Drive expirou ou foi revogada; reconecte")
	}
	t.Access = v.Access
	t.Expires = time.Now().Add(time.Duration(v.Expires) * time.Second)
	if e = a.storeDriveToken(email, t); e != nil {
		return "", e
	}
	return t.Access, nil
}
func driveRequest(method, target, access string, body io.Reader, contentType string) (*http.Response, error) {
	req, e := http.NewRequest(method, target, body)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+access)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, errors.New("Drive indisponível")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, errors.New("Drive recusou a operação; confira autorização e espaço disponível")
	}
	return resp, nil
}
func driveOwner(email string) string {
	h := sha256.Sum256([]byte(strings.ToLower(email)))
	return hex.EncodeToString(h[:])
}
func (a *App) uploadDriveBackup(email string, data []byte) error {
	a.driveMu.Lock()
	defer a.driveMu.Unlock()
	access, e := a.driveAccess(email)
	if e != nil {
		return e
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	meta, _ := json.Marshal(map[string]any{"name": "Multipla-Siem-1.1-" + time.Now().UTC().Format("20060102-150405") + ".json", "mimeType": "application/json", "appProperties": map[string]string{"product": "multipla-siem", "schema": "1", "owner": driveOwner(email)}})
	header := textproto.MIMEHeader{}
	header.Set("Content-Type", "application/json; charset=UTF-8")
	part, e := writer.CreatePart(header)
	if e != nil {
		return e
	}
	part.Write(meta)
	part, e = writer.CreatePart(header)
	if e != nil {
		return e
	}
	part.Write(data)
	writer.Close()
	resp, e := driveRequest("POST", "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id", access, &body, "multipart/related; boundary="+writer.Boundary())
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	var result DriveFile
	if json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&result) != nil || !driveID.MatchString(result.ID) {
		return errors.New("resposta Drive inválida")
	}
	return nil
}
func (a *App) listDriveBackups(email string) ([]DriveFile, error) {
	a.driveMu.Lock()
	defer a.driveMu.Unlock()
	access, e := a.driveAccess(email)
	if e != nil {
		return nil, e
	}
	q := url.Values{"q": {"trashed = false and appProperties has { key='product' and value='multipla-siem' } and appProperties has { key='owner' and value='" + driveOwner(email) + "' }"}, "fields": {"files(id,name,createdTime,size),nextPageToken"}, "orderBy": {"createdTime desc"}, "pageSize": {"100"}}
	resp, e := driveRequest("GET", "https://www.googleapis.com/drive/v3/files?"+q.Encode(), access, nil, "")
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	var result struct {
		Files []DriveFile `json:"files"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 262144)).Decode(&result) != nil {
		return nil, errors.New("listagem Drive inválida")
	}
	return result.Files, nil
}
func (a *App) restoreDriveBackup(email, id string) error {
	if !driveID.MatchString(id) {
		return errors.New("ID Drive inválido")
	}
	a.driveMu.Lock()
	defer a.driveMu.Unlock()
	access, e := a.driveAccess(email)
	if e != nil {
		return e
	}
	target := "https://www.googleapis.com/drive/v3/files/" + id
	resp, e := driveRequest("GET", target+"?fields=id,appProperties,mimeType,trashed", access, nil, "")
	if e != nil {
		return e
	}
	var file DriveFile
	e = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&file)
	resp.Body.Close()
	if e != nil || file.ID != id || file.Trashed || file.Mime != "application/json" || file.Properties["product"] != "multipla-siem" || file.Properties["owner"] != driveOwner(email) || file.Properties["schema"] != "1" {
		return errors.New("arquivo não é um backup autorizado desta conta")
	}
	resp, e = driveRequest("GET", target+"?alt=media", access, nil, "")
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, backupLimit+1))
	if e != nil || len(data) > backupLimit {
		return errors.New("backup Drive inválido ou muito grande")
	}
	return a.restoreBackup(email, data)
}
func (a *App) registerDriveRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/drive/connect", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		if a.demo || s.Email == "bootstrap" || s.Subject == "" {
			http.Error(w, "Entre com Google para vincular o Drive", 400)
			return
		}
		if _, e := driveCipher(); e != nil {
			http.Error(w, e.Error(), 503)
			return
		}
		if a.googleSecret("GOOGLE_CLIENT_ID") == "" || a.googleSecret("GOOGLE_CLIENT_SECRET") == "" {
			http.Error(w, "Configure OAuth Google", 503)
			return
		}
		state, verifier := token(), token()
		a.mu.Lock()
		if len(a.oauth) >= 1000 {
			a.mu.Unlock()
			http.Error(w, "limite OAuth", 429)
			return
		}
		a.oauth[state] = OAuth{Verifier: verifier, Expires: time.Now().Add(5 * time.Minute), DriveEmail: s.Email, DriveSubject: s.Subject}
		a.mu.Unlock()
		a.cookie(w, a.oauthName(), state, 300)
		hash := sha256.Sum256([]byte(verifier))
		q := url.Values{"client_id": {a.googleSecret("GOOGLE_CLIENT_ID")}, "redirect_uri": {a.origin + "/auth/callback"}, "response_type": {"code"}, "scope": {"openid email " + driveScope}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"}, "access_type": {"offline"}, "prompt": {"consent"}, "login_hint": {s.Email}}
		writeJSON(w, map[string]string{"url": "https://accounts.google.com/o/oauth2/v2/auth?" + q.Encode()})
	}))
	mux.HandleFunc("GET /api/drive/backups", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		files, e := a.listDriveBackups(s.Email)
		if e != nil {
			http.Error(w, e.Error(), 502)
			return
		}
		writeJSON(w, map[string]any{"files": files})
	}))
	mux.HandleFunc("POST /api/drive/backups/{id}/restore", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		if e := a.restoreDriveBackup(s.Email, r.PathValue("id")); e != nil {
			http.Error(w, "Não restaurado: "+e.Error(), 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/drive/disconnect", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.driveMu.Lock()
		defer a.driveMu.Unlock()
		a.mu.Lock()
		defer a.mu.Unlock()
		key := strings.ToLower(s.Email)
		old := a.state.DriveTokens[key]
		delete(a.state.DriveTokens, key)
		p := a.preferences(s.Email)
		previous := p
		p.BackupDrive = false
		a.state.Preferences[key] = p
		if e := a.persist(); e != nil {
			a.state.DriveTokens[key] = old
			a.state.Preferences[key] = previous
			http.Error(w, "falha ao desconectar", 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
