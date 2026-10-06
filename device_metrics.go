package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
)

//go:embed scripts/windows-collector.ps1
var windowsCollector string

//go:embed scripts/linux-collector-install.sh
var linuxCollectorInstaller string

//go:embed scripts/linux-collector.py
var linuxCollectorBody string

func linuxCollectorDownload() string {
	return strings.Replace(linuxCollectorInstaller, "__COLLECTOR_BODY__", linuxCollectorBody, 1)
}

type DeviceDiskMetric struct {
	Drive       string  `json:"drive"`
	UsedPercent float64 `json:"used_percent"`
}
type DeviceTelemetry struct {
	Hostname     string             `json:"hostname"`
	CPU          float64            `json:"cpu"`
	Memory       float64            `json:"memory"`
	Disks        []DeviceDiskMetric `json:"disks"`
	ReceiveBytes float64            `json:"receive_bytes_per_second"`
	SendBytes    float64            `json:"send_bytes_per_second"`
	Received     time.Time          `json:"received"`
}

func metricTokenHash(t string) string { h := sha256.Sum256([]byte(t)); return hex.EncodeToString(h[:]) }
func validateDeviceTelemetry(m DeviceTelemetry) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,253}$`).MatchString(m.Hostname) || len(m.Disks) > 32 {
		return errors.New("hostname ou discos inválidos")
	}
	for _, v := range []float64{m.CPU, m.Memory} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 100 {
			return errors.New("percentual inválido")
		}
	}
	for _, v := range []float64{m.ReceiveBytes, m.SendBytes} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1e15 {
			return errors.New("taxa de rede inválida")
		}
	}
	for _, d := range m.Disks {
		if (len(d.Drive) > 120 || !regexp.MustCompile(`^(?:[A-Z]:|/[a-zA-Z0-9_./ -]*)$`).MatchString(d.Drive)) || math.IsNaN(d.UsedPercent) || d.UsedPercent < 0 || d.UsedPercent > 100 {
			return errors.New("disco inválido")
		}
	}
	return nil
}
func (a *App) registerDeviceMetricRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/devices/collector", a.auth(func(w http.ResponseWriter, r *http.Request) {
		platform := r.URL.Query().Get("platform")
		if platform != "" && platform != "windows" && platform != "linux" {
			http.Error(w, "Plataforma inválida", 400)
			return
		}
		if platform == "linux" {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="linux-collector-install.sh"`)
			w.Write([]byte(linuxCollectorDownload()))
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="windows-collector.ps1"`)
		w.Write([]byte(windowsCollector))
	}))
	mux.HandleFunc("POST /api/devices/metrics-key", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IP     string `json:"ip"`
			Revoke bool   `json:"revoke"`
		}
		if !decode(w, r, &body) {
			return
		}
		d, ok := a.registeredDevice(body.IP)
		if !ok {
			http.NotFound(w, r)
			return
		}
		key := token()
		current, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.state.MetricKeys == nil {
			a.state.MetricKeys = map[string]string{}
		}
		old := a.state.MetricKeys[d.IP]
		if body.Revoke {
			delete(a.state.MetricKeys, d.IP)
		} else {
			a.state.MetricKeys[d.IP] = metricTokenHash(key)
		}
		a.audit(current.Email, "chave de coletor alterada: "+d.Name)
		if err := a.persist(); err != nil {
			if old == "" {
				delete(a.state.MetricKeys, d.IP)
			} else {
				a.state.MetricKeys[d.IP] = old
			}
			http.Error(w, "falha ao salvar chave", 500)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if body.Revoke {
			writeJSON(w, map[string]bool{"revoked": true})
		} else {
			writeJSON(w, map[string]string{"key": key, "ip": d.IP, "note": "Chave exclusiva para enviar métricas deste dispositivo; exibida uma vez. Uma nova chave revoga a anterior."})
		}
	}))
	// Agent endpoint is intentionally independent of web sessions; keys cannot access any other API.
	mux.HandleFunc("POST /api/device-metrics/{ip}", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || a.demo {
			http.Error(w, "HTTPS obrigatório", 403)
			return
		}
		ip := r.PathValue("ip")
		d, ok := a.registeredDevice(ip)
		if !ok {
			http.NotFound(w, r)
			return
		}
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(key) < 32 || len(key) > 128 {
			http.Error(w, "não autorizado", 401)
			return
		}
		a.mu.Lock()
		expected := a.state.MetricKeys[d.IP]
		a.mu.Unlock()
		if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(metricTokenHash(key))) != 1 {
			http.Error(w, "não autorizado", 401)
			return
		}
		var data DeviceTelemetry
		if !decode(w, r, &data) {
			return
		}
		if err := validateDeviceTelemetry(data); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		data.Received = time.Now().UTC()
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.state.MetricKeys[d.IP] != expected {
			http.Error(w, "chave revogada", 401)
			return
		}
		if a.state.DeviceMetrics == nil {
			a.state.DeviceMetrics = map[string]DeviceTelemetry{}
		}
		old, had := a.state.DeviceMetrics[d.IP]
		if time.Since(old.Received) < 10*time.Second {
			http.Error(w, "aguarde entre envios", 429)
			return
		}
		a.state.DeviceMetrics[d.IP] = data
		if err := a.persist(); err != nil {
			if had {
				a.state.DeviceMetrics[d.IP] = old
			} else {
				delete(a.state.DeviceMetrics, d.IP)
			}
			http.Error(w, "armazenamento indisponível", 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/devices/metrics", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		visible := map[string]DeviceTelemetry{}
		for _, d := range a.cfg.Devices {
			if m, ok := a.state.DeviceMetrics[d.IP]; ok {
				visible[d.IP] = m
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, visible)
	}))
}
