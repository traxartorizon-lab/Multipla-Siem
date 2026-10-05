package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func fullDriveAccess(email string) (string, error) {
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return "", errors.New("email Drive invalido")
	}
	values, err := readCredentialValues("/etc/multipla-siem/secrets.env")
	if err != nil {
		return "", err
	}
	credentialValues = values
	data, err := os.ReadFile("/var/lib/multipla-siem/config.json")
	if err != nil {
		return "", err
	}
	var cfg Config
	if json.Unmarshal(data, &cfg) != nil {
		return "", errors.New("configuracao invalida")
	}
	allowed := false
	for _, account := range cfg.AllowedEmails {
		if strings.EqualFold(account, email) {
			allowed = true
		}
	}
	if !allowed {
		return "", errors.New("conta nao autorizada")
	}
	data, err = os.ReadFile("/var/lib/multipla-siem/state.json")
	if err != nil {
		return "", err
	}
	var state State
	if json.Unmarshal(data, &state) != nil {
		return "", errors.New("estado invalido")
	}
	if account, exists := state.Accounts[strings.ToLower(email)]; exists && (account.Disabled || account.Role != "admin") {
		return "", errors.New("backup completo exige conta administrativa")
	}
	t, err := openDriveToken(strings.ToLower(email), state.DriveTokens[strings.ToLower(email)])
	if err != nil {
		return "", errors.New("autorize o Drive no painel com esta conta")
	}
	granted := false
	for _, scope := range strings.Fields(t.Scope) {
		if scope == driveScope {
			granted = true
		}
	}
	if !granted || t.Subject == "" || t.Subject != state.GoogleSubjects[strings.ToLower(email)] {
		return "", errors.New("identidade ou permissao Drive invalida")
	}
	if time.Now().Add(time.Minute).Before(t.Expires) {
		return t.Access, nil
	}
	id, secretValue := secret("GOOGLE_CLIENT_ID"), secret("GOOGLE_CLIENT_SECRET")
	if state.GoogleSettings != "" {
		settings, err := openDriveToken("multipla-oauth-config", state.GoogleSettings)
		if err != nil {
			return "", err
		}
		id, secretValue = settings.Access, settings.Refresh
	}
	resp, err := client.PostForm("https://oauth2.googleapis.com/token", url.Values{"client_id": {id}, "client_secret": {secretValue}, "grant_type": {"refresh_token"}, "refresh_token": {t.Refresh}})
	if err != nil {
		return "", errors.New("Google indisponivel")
	}
	defer resp.Body.Close()
	var token struct {
		Access  string `json:"access_token"`
		Expires int    `json:"expires_in"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&token) != nil || len(token.Access) < 1 || len(token.Access) > 4096 || token.Expires <= 0 {
		return "", errors.New("autorizacao Drive expirada ou revogada; reconecte a conta")
	}
	// Do not rewrite state.json from a root helper while the application runs.
	return token.Access, nil
}

func validFullUploadURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "www.googleapis.com" && u.User == nil && u.Path == "/upload/drive/v3/files" && u.Fragment == "" && u.Query().Get("upload_id") != ""
}

func uploadFullDrive(email, file string) error {
	access, err := fullDriveAccess(email)
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	meta, _ := json.Marshal(map[string]any{"name": "Multipla-Siem-full-" + time.Now().UTC().Format("20060102-150405") + ".msbk", "mimeType": "application/octet-stream", "appProperties": map[string]string{"product": "multipla-siem-full", "schema": "1", "owner": driveOwner(email)}})
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	uploadClient := &http.Client{Transport: transport, Timeout: 30 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirecionamento Drive recusado") }}
	req, err := http.NewRequest("POST", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id,size,md5Checksum", bytes.NewReader(meta))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Upload-Content-Type", "application/octet-stream")
	req.Header.Set("X-Upload-Content-Length", strconv.FormatInt(info.Size(), 10))
	resp, err := uploadClient.Do(req)
	if err != nil {
		return errors.New("nao foi possivel iniciar envio Drive")
	}
	location := resp.Header.Get("Location")
	resp.Body.Close()
	if resp.StatusCode != 200 || !validFullUploadURL(location) {
		return errors.New("sessao de envio Drive invalida")
	}
	digest := md5.New() // Transport checksum only; backup authentication is AES-GCM.
	req, err = http.NewRequest("PUT", location, io.TeeReader(f, digest))
	if err != nil {
		return err
	}
	req.ContentLength = info.Size()
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err = uploadClient.Do(req)
	if err != nil {
		return errors.New("envio Drive interrompido; copia local preservada")
	}
	defer resp.Body.Close()
	var result struct {
		ID   string `json:"id"`
		Size string `json:"size"`
		MD5  string `json:"md5Checksum"`
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("Drive recusou backup completo (HTTP %d)", resp.StatusCode)
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&result) != nil || !driveID.MatchString(result.ID) || result.Size != strconv.FormatInt(info.Size(), 10) || result.MD5 != hex.EncodeToString(digest.Sum(nil)) {
		return errors.New("integridade do envio Drive nao confirmada; copia local preservada")
	}
	return nil
}
