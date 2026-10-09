package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ResourceSample struct {
	Time       time.Time        `json:"time"`
	Metrics    *DeviceTelemetry `json:"metrics,omitempty"`
	Sent       int              `json:"sent"`
	Received   int              `json:"received"`
	LatencyAvg *float64         `json:"latency_avg_ms,omitempty"`
	LatencyMax *float64         `json:"latency_max_ms,omitempty"`
	PingError  string           `json:"ping_error,omitempty"`
}

var pingPacketRE = regexp.MustCompile(`(?m)(\d+) packets transmitted, (\d+) (?:packets )?received`)
var pingLatencyRE = regexp.MustCompile(`(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = [0-9.]+/([0-9.]+)/([0-9.]+)/`)

func parseResourcePing(output string, err error) ResourceSample {
	sample := ResourceSample{}
	if m := pingPacketRE.FindStringSubmatch(output); len(m) == 3 {
		sample.Sent, _ = strconv.Atoi(m[1])
		sample.Received, _ = strconv.Atoi(m[2])
	}
	if m := pingLatencyRE.FindStringSubmatch(output); len(m) == 3 {
		avg, _ := strconv.ParseFloat(m[1], 64)
		max, _ := strconv.ParseFloat(m[2], 64)
		sample.LatencyAvg = &avg
		sample.LatencyMax = &max
	}
	if sample.Sent != 3 || sample.Received > sample.Sent {
		sample.Sent = 0
		sample.Received = 0
		sample.LatencyAvg = nil
		sample.LatencyMax = nil
		sample.PingError = "Medição indisponível"
	} else if err != nil && sample.Received == 0 {
		sample.PingError = "Sem resposta ICMP"
	}
	return sample
}
func (a *App) resourceHistoryPath(ip string) string {
	return filepath.Join(a.cfg.DataDir, "resource-history", metricTokenHash(ip)+".json")
}
func (a *App) readResourceHistory(ip string) ([]ResourceSample, error) {
	path := a.resourceHistoryPath(ip)
	if err := regularFile(path); os.IsNotExist(err) {
		return []ResourceSample{}, nil
	} else if err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > 8<<20 {
		return nil, errors.New("histórico muito grande")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var samples []ResourceSample
	err = json.Unmarshal(data, &samples)
	return samples, err
}
func retainResourceSamples(samples []ResourceSample, now time.Time) []ResourceSample {
	cut := now.Add(-24 * time.Hour)
	minutes := map[int64]ResourceSample{}
	for _, sample := range samples {
		if sample.Time.Before(cut) || sample.Time.After(now) {
			continue
		}
		minute := sample.Time.Truncate(time.Minute).Unix()
		if old, ok := minutes[minute]; !ok || sample.Time.After(old.Time) {
			minutes[minute] = sample
		}
	}
	result := make([]ResourceSample, 0, len(minutes))
	for _, sample := range minutes {
		result = append(result, sample)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Time.Before(result[j].Time) })
	if len(result) > 1440 {
		result = result[len(result)-1440:]
	}
	return result
}
func (a *App) collectResourceSample(ip string) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return
	}
	if _, ok := a.registeredDevice(ip); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/ping", "-n", "-c", "3", "-W", "2", "-w", "7", "--", ip)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	output, err := cmd.Output()
	sample := parseResourcePing(string(output), err)
	sample.Time = time.Now().UTC()
	a.mu.Lock()
	metric, ok := a.state.DeviceMetrics[ip]
	registered := false
	for _, d := range a.cfg.Devices {
		if d.IP == ip {
			registered = true
			break
		}
	}
	a.mu.Unlock()
	if !registered {
		return
	}
	if ok && !metric.Received.After(sample.Time) && sample.Time.Sub(metric.Received) <= 90*time.Second {
		copy := metric
		sample.Metrics = &copy
	}
	a.resourceHistoryMu.Lock()
	defer a.resourceHistoryMu.Unlock()
	samples, readErr := a.readResourceHistory(ip)
	if readErr != nil {
		return
	}
	samples = retainResourceSamples(append(samples, sample), sample.Time)
	dir := filepath.Dir(a.resourceHistoryPath(ip))
	if os.MkdirAll(dir, 0700) != nil {
		return
	}
	if err := atomicJSON(a.resourceHistoryPath(ip), samples); err != nil {
		a.mu.Lock()
		a.storageError = "Falha ao salvar histórico de recursos"
		a.mu.Unlock()
	}
}
func (a *App) resourceHistoryWorker() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		a.mu.Lock()
		ips := map[string]bool{}
		for _, p := range a.state.Preferences {
			for _, c := range p.DashboardCards {
				if c.Device != "" {
					ips[c.Device] = true
				}
			}
		}
		for _, d := range a.cfg.Devices {
			if d.Kind == "windows" || d.Kind == "linux" || d.Kind == "proxmox" {
				ips[d.IP] = true
			}
		}
		demo := a.demo
		a.mu.Unlock()
		if !demo {
			slots := make(chan struct{}, 8)
			var wg sync.WaitGroup
			for ip := range ips {
				slots <- struct{}{}
				wg.Add(1)
				go func(ip string) { defer wg.Done(); defer func() { <-slots }(); a.collectResourceSample(ip) }(ip)
			}
			wg.Wait()
		}
		<-ticker.C
	}
}
func (a *App) registerResourceHistoryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/devices/resource-history", a.auth(func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimSpace(r.URL.Query().Get("ip"))
		if _, ok := a.registeredDevice(ip); !ok {
			http.NotFound(w, r)
			return
		}
		a.resourceHistoryMu.Lock()
		samples, err := a.readResourceHistory(ip)
		a.resourceHistoryMu.Unlock()
		if err != nil {
			http.Error(w, "Histórico indisponível", 500)
			return
		}
		now := time.Now().UTC()
		samples = retainResourceSamples(samples, now)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"ip": ip, "from": now.Add(-24 * time.Hour), "to": now, "samples": samples, "interval_seconds": 60})
	}))
}
