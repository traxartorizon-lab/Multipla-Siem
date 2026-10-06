package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type activityHistoryGroup struct {
	Name  string    `json:"name"`
	Bins  []float64 `json:"bins"`
	Total int       `json:"total"`
}

func activityDuration(p string) (time.Duration, bool) {
	switch p {
	case "30m":
		return 30 * time.Minute, true
	case "1h":
		return time.Hour, true
	case "6h":
		return 6 * time.Hour, true
	case "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	}
	return 0, false
}
func (a *App) serveActivityHistory(w http.ResponseWriter, r *http.Request) {
	duration, ok := activityDuration(r.URL.Query().Get("period"))
	mode := r.URL.Query().Get("mode")
	if !ok || (mode != "average" && mode != "maximum") {
		http.Error(w, "intervalo invalido", 400)
		return
	}
	select {
	case reportSlots <- struct{}{}:
		defer func() { <-reportSlots }()
	default:
		http.Error(w, "consulta ocupada", 429)
		return
	}
	a.mu.Lock()
	dir := a.cfg.DataDir
	devices := append([]Device(nil), a.cfg.Devices...)
	a.mu.Unlock()
	end := time.Now().UTC()
	start := end.Add(-duration).Truncate(time.Minute)
	minutes := int(end.Sub(start)/time.Minute) + 1
	step := (minutes + 119) / 120
	count := (minutes + step - 1) / step
	groups := map[string][]int{}
	partial := false
	missing := []string{}
	for _, d := range devices {
		if len(groups) < 256 {
			groups[d.Name] = make([]int, minutes)
		}
	}
	remaining := int64(64 << 20)
	deadline := time.Now().Add(10 * time.Second)
	for day := end.Truncate(24 * time.Hour); !day.Before(start.Truncate(24 * time.Hour)); day = day.AddDate(0, 0, -1) {
		if remaining <= 0 || time.Now().After(deadline) {
			partial = true
			break
		}
		file, err := os.Open(filepath.Join(dir, "events-"+day.Format("2006-01-02")+".jsonl"))
		if os.IsNotExist(err) {
			missing = append(missing, day.Format("2006-01-02"))
			continue
		}
		if err != nil {
			http.Error(w, "historico indisponivel", 503)
			return
		}
		reader := &io.LimitedReader{R: file, N: remaining + 1}
		scan := bufio.NewScanner(reader)
		scan.Buffer(make([]byte, 65536), 256<<10)
		for scan.Scan() {
			if r.Context().Err() != nil {
				file.Close()
				return
			}
			if reader.N <= 1 || time.Now().After(deadline) {
				partial = true
				break
			}
			var event Event
			if json.Unmarshal(scan.Bytes(), &event) != nil || event.Alert || event.Time.Before(start) || event.Time.After(end) {
				continue
			}
			name := event.Device
			if name == "" {
				name = "Dispositivo não identificado"
			}
			if groups[name] == nil {
				if len(groups) >= 256 {
					name = "Outros dispositivos"
					partial = true
				}
				if groups[name] == nil {
					groups[name] = make([]int, minutes)
				}
			}
			index := int(event.Time.Sub(start) / time.Minute)
			if index >= 0 && index < minutes {
				groups[name][index]++
			}
		}
		if scan.Err() != nil {
			partial = true
		}
		remaining -= (remaining + 1 - reader.N)
		file.Close()
		if partial && remaining <= 0 {
			break
		}
	}
	times := make([]time.Time, count)
	for i := range times {
		times[i] = start.Add(time.Duration(i*step) * time.Minute)
	}
	out := []activityHistoryGroup{}
	for name, counts := range groups {
		item := activityHistoryGroup{Name: name, Bins: make([]float64, count)}
		for i, n := range counts {
			item.Total += n
			bucket := i / step
			if mode == "maximum" {
				if float64(n) > item.Bins[bucket] {
					item.Bins[bucket] = float64(n)
				}
			} else {
				item.Bins[bucket] += float64(n)
			}
		}
		if mode == "average" {
			for i := range item.Bins {
				size := step
				if left := minutes - i*step; left < size {
					size = left
				}
				item.Bins[i] /= float64(size)
			}
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total == out[j].Total {
			return out[i].Name < out[j].Name
		}
		return out[i].Total > out[j].Total
	})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"series": out, "times": times, "partial": partial, "missing_days": missing, "interval_minutes": step})
}
