package main

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

//go:embed deploy/49-multipla-reboot.rules
var rebootPolicy string

func enableServerReboot() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("execute como root no servidor Linux")
	}
	dir := "/etc/polkit-1/rules.d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	path := filepath.Join(dir, "49-multipla-reboot.rules")
	if err := regularFile(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(dir, ".multipla-reboot-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.WriteString(rebootPolicy); err != nil {
		file.Close()
		return err
	}
	if err = file.Chmod(0644); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

var dashboardReportCache struct {
	sync.Mutex
	key    string
	until  time.Time
	report eventReport
}

func (a *App) registerSystemRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/dashboard/distribution", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		dataDir := a.cfg.DataDir
		a.mu.Unlock()
		dashboardReportCache.Lock()
		defer dashboardReportCache.Unlock()
		now := time.Now().UTC()
		if dashboardReportCache.key != dataDir || now.After(dashboardReportCache.until) {
			select {
			case reportSlots <- struct{}{}:
				defer func() { <-reportSlots }()
			default:
				http.Error(w, "consulta de histórico em andamento", 429)
				return
			}
			start := now.Add(-24 * time.Hour)
			f := reportFilter{Type: "logs", cutoff: start}
			report, err := a.buildReport(r, f, start.Truncate(24*time.Hour), now.Truncate(24*time.Hour))
			if err != nil {
				http.Error(w, "histórico indisponível", 503)
				return
			}
			report.Events = nil
			dashboardReportCache.key = dataDir
			dashboardReportCache.report = report
			dashboardReportCache.until = now.Add(time.Minute)
		}
		writeJSON(w, map[string]any{"by_device": dashboardReportCache.report.ByDevice, "total": dashboardReportCache.report.Originals, "partial": dashboardReportCache.report.Partial, "missing_days": dashboardReportCache.report.Missing, "generated": dashboardReportCache.report.Generated})
	}))
	mux.HandleFunc("POST /api/system/reboot", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Confirm string `json:"confirm"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.Confirm != "REINICIAR" {
			http.Error(w, "confirme digitando REINICIAR", 400)
			return
		}
		if a.demo || runtime.GOOS != "linux" {
			http.Error(w, "reinício disponível somente no servidor Linux em produção", 403)
			return
		}
		current, _ := a.session(r)
		a.mu.Lock()
		a.audit(current.Email, "reinício desta VM solicitado")
		err := a.persist()
		a.mu.Unlock()
		if err != nil {
			http.Error(w, "auditoria indisponível; reinício cancelado", 500)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		// Explicit login1 operation. No shell, sudo, privileged SIEM or arbitrary unit control.
		err = exec.CommandContext(ctx, "/usr/bin/busctl", "call", "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "Reboot", "b", "false").Run()
		if err != nil {
			http.Error(w, "reinício recusado pelo sistema; habilite a política restrita descrita em NETWORK-TOOLS.md", 503)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
