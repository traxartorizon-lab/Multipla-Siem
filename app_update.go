package main

import (
	"context"
	_ "embed"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed scripts/multipla-update
var appUpdaterEntry string

//go:embed deploy/multipla-app-update.service
var appUpdateUnit string

//go:embed deploy/49-multipla-app-update.rules
var appUpdatePolicy string

var appUpdateGate sync.Mutex

func enableAppUpdate() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("execute como root no servidor Linux")
	}
	if err := os.WriteFile("/usr/local/bin/multipla-update", []byte(appUpdaterEntry), 0755); err != nil {
		return err
	}
	for path, content := range map[string]string{
		"/etc/systemd/system/multipla-app-update.service":    appUpdateUnit,
		"/etc/polkit-1/rules.d/49-multipla-app-update.rules": appUpdatePolicy,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if err := regularFile(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return err
		}
		if err := os.Chown(path, 0, 0); err != nil {
			return err
		}
		if err := os.Chmod(path, 0644); err != nil {
			return err
		}
	}
	return exec.Command("/usr/bin/systemctl", "daemon-reload").Run()
}

func appUpdateStatus(ctx context.Context) (map[string]string, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("atualização requer servidor Linux")
	}
	b, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "multipla-app-update.service", "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,ActiveEnterTimestamp,InactiveEnterTimestamp").Output()
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			result[key] = value
		}
	}
	return result, nil
}

func (a *App) registerUpdateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/system/update", a.auth(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		status, err := appUpdateStatus(ctx)
		if err != nil {
			http.Error(w, "Serviço de atualização indisponível", 503)
			return
		}
		writeJSON(w, map[string]any{"status": status, "version": productVersion()})
	}))
	mux.HandleFunc("POST /api/system/update", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if a.demo || runtime.GOOS != "linux" || r.TLS == nil {
			http.Error(w, "Atualização exige HTTPS no servidor de produção", 403)
			return
		}
		var input struct {
			Confirm  string `json:"confirm"`
			Password string `json:"password"`
		}
		if !decode(w, r, &input) {
			return
		}
		s, _ := a.session(r)
		googleMFA := a.mfaRequired() && s.Subject != "" && !s.MFATime.IsZero() && time.Since(s.MFATime) <= 5*time.Minute
		if input.Confirm != "ATUALIZAR" || (!googleMFA && (len(input.Password) < 14 || len(input.Password) > 256)) {
			http.Error(w, "Confirme ATUALIZAR e informe sua senha", 400)
			return
		}
		if !a.takeRate("step-up-update:"+strings.ToLower(s.Email), 5, time.Minute) {
			http.Error(w, "Limite de reautenticação; aguarde um minuto", 429)
			return
		}
		a.mu.Lock()
		account := a.state.Accounts[strings.ToLower(s.Email)]
		identity := a.desktopAccountDigest(strings.ToLower(s.Email))
		salt, stored := account.Salt, account.Hash
		if strings.EqualFold(s.Email, a.state.LocalAdmin.Email) {
			salt, stored = a.state.LocalAdmin.Salt, a.state.LocalAdmin.Hash
		}
		a.mu.Unlock()
		hash := ""
		var err error
		if !googleMFA {
			hash, err = passwordHash(input.Password, salt)
		}
		input.Password = ""
		if !googleMFA && (err != nil || stored == "" || !equal(hash, stored)) {
			http.Error(w, "Reautenticação recusada; conta deve ter credencial local para esta operação", 403)
			return
		}
		if !appUpdateGate.TryLock() {
			http.Error(w, "Atualização já solicitada", 409)
			return
		}
		defer appUpdateGate.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		status, err := appUpdateStatus(ctx)
		if err != nil || status["LoadState"] != "loaded" {
			http.Error(w, "Habilite o serviço restrito de atualização conforme WINDOWS-APP.md", 503)
			return
		}
		if status["ActiveState"] == "activating" || status["ActiveState"] == "active" {
			http.Error(w, "Atualização em andamento", 409)
			return
		}
		a.mu.Lock()
		// Recheck privilege after the expensive password verification.
		if a.groupLocked(s.Email) != groupSuperadmin || !equal(identity, a.desktopAccountDigest(strings.ToLower(s.Email))) {
			a.mu.Unlock()
			http.Error(w, "Permissão alterada", 403)
			return
		}
		if time.Since(a.state.AppUpdateRequested) < time.Minute {
			a.mu.Unlock()
			http.Error(w, "Aguarde um minuto antes de nova tentativa", 429)
			return
		}
		previous := a.state.AppUpdateRequested
		a.state.AppUpdateRequested = time.Now().UTC()
		a.audit(s.Email, "atualização assinada solicitada pelo app/painel")
		if a.persist() != nil {
			a.state.AppUpdateRequested = previous
			a.mu.Unlock()
			http.Error(w, "Auditoria indisponível; atualização cancelada", 503)
			return
		}
		a.mu.Unlock()
		// Fixed operation only; no user-provided command, path, unit, URL or shell.
		err = exec.CommandContext(ctx, "/usr/bin/busctl", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartUnit", "ss", "multipla-app-update.service", "replace").Run()
		if err != nil {
			http.Error(w, "Sistema recusou iniciar atualização; consulte o serviço restrito", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, map[string]any{"ok": true, "message": "Atualização iniciada. O painel poderá ficar temporariamente indisponível; aguarde reconexão."})
	}))
}
