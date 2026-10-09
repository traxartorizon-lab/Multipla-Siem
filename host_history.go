package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type HostUsageSample struct {
	Time   time.Time `json:"time"`
	CPU    *float64  `json:"cpu,omitempty"`
	Memory *float64  `json:"memory,omitempty"`
	Disk   *float64  `json:"disk,omitempty"`
}

func retainHostUsage(samples []HostUsageSample, now time.Time) []HostUsageSample {
	minutes := map[int64]HostUsageSample{}
	for _, s := range samples {
		if s.Time.Before(now.Add(-24*time.Hour)) || s.Time.After(now) {
			continue
		}
		clean := func(v *float64) *float64 {
			if v == nil || math.IsNaN(*v) || math.IsInf(*v, 0) || *v < 0 || *v > 100 {
				return nil
			}
			return v
		}
		s.CPU = clean(s.CPU)
		s.Memory = clean(s.Memory)
		s.Disk = clean(s.Disk)
		key := s.Time.Truncate(time.Minute).Unix()
		if old, ok := minutes[key]; !ok || s.Time.After(old.Time) {
			minutes[key] = s
		}
	}
	result := []HostUsageSample{}
	for _, s := range minutes {
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Time.Before(result[j].Time) })
	if len(result) > 1440 {
		result = result[len(result)-1440:]
	}
	return result
}
func readHostUsage(path string) ([]HostUsageSample, error) {
	if err := regularFile(path); os.IsNotExist(err) {
		return []HostUsageSample{}, nil
	} else if err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > 1<<20 {
		return nil, fmt.Errorf("histórico do servidor excede limite")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var samples []HostUsageSample
	err = json.Unmarshal(data, &samples)
	return samples, err
}
func (a *App) recordHostUsage(dir string, h HostHealth) error {
	a.resourceHistoryMu.Lock()
	defer a.resourceHistoryMu.Unlock()
	path := filepath.Join(dir, "host-usage.json")
	samples, err := readHostUsage(path)
	if err != nil {
		return err
	}
	samples = append(samples, HostUsageSample{Time: h.Time, CPU: h.CPU, Memory: h.Memory, Disk: h.Disk})
	return atomicJSON(path, retainHostUsage(samples, h.Time))
}
func lowHostDisk(h HostHealth, previous bool) bool {
	if h.Disk == nil {
		return false
	}
	low := *h.Disk >= 90 || (h.DiskFreeBytes != nil && *h.DiskFreeBytes <= 1<<30)
	if previous {
		low = low || *h.Disk >= 88 || (h.DiskFreeBytes != nil && *h.DiskFreeBytes <= uint64(1.25*float64(1<<30)))
	}
	return low
}
func (a *App) registerHostHistoryRoute(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/system/usage-history", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		dir := a.cfg.DataDir
		a.mu.Unlock()
		a.resourceHistoryMu.Lock()
		samples, err := readHostUsage(filepath.Join(dir, "host-usage.json"))
		a.resourceHistoryMu.Unlock()
		if err != nil {
			http.Error(w, "Histórico do servidor indisponível", 500)
			return
		}
		now := time.Now().UTC()
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"samples": retainHostUsage(samples, now), "from": now.Add(-24 * time.Hour), "to": now})
	}))
}
