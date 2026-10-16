package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type capacityLedger struct {
	Day    string
	Bytes  map[string]int64
	Warned map[string]bool
}

const spoolMaxBytes int64 = 64 << 20
const spoolMaxRecords = 2048

func (a *App) capacitySignal(reason string, e Event, dropped bool) {
	if dropped {
		a.dropped++
	}
	a.storageError = reason
	// journald is independent of the application event quota. Never include raw logs.
	key := "capacity:" + reason + ":" + e.SenderIP
	now := time.Now()
	if now.Sub(a.seen[key]) >= time.Minute {
		a.seen[key] = now
		log.Printf("SIEM_CAPACITY reason=%q sender=%q discarded=%t", reason, e.SenderIP, dropped)
		a.addNotification(SystemNotification{Tenant: e.Tenant, ID: token(), Time: now.UTC(), Title: "Capacidade da coleta", Detail: reason + " · origem " + e.SenderIP, Severity: "critical"})
	}
}
func (a *App) ingestRateLocked(e Event) bool {
	critical := a.classifiedEvent(e).Level >= 12
	key := "ingest:" + e.SenderIP
	global := "ingest:global"
	limit := 200
	globalLimit := 2000
	if critical {
		key += ":critical"
		global += ":critical"
		limit = 50
		globalLimit = 500
	}
	now := time.Now()
	for _, k := range []string{key, global} {
		b := a.rates[k]
		if now.Sub(b.Start) >= time.Second {
			b = rateWindow{Start: now}
		}
		max := limit
		if k == global {
			max = globalLimit
		}
		if b.Count >= max {
			a.capacitySignal("taxa por origem ou global excedida", e, true)
			return false
		}
	}
	for _, k := range []string{key, global} {
		b := a.rates[k]
		if now.Sub(b.Start) >= time.Second {
			b = rateWindow{Start: now}
		}
		b.Count++
		a.rates[k] = b
	}
	return true
}
func (a *App) journalQuota(e Event, bytes int64) bool {
	day := e.Time.UTC().Format("2006-01-02")
	if a.capacity.Day != day {
		a.capacity = capacityLedger{Day: day, Bytes: map[string]int64{}, Warned: map[string]bool{}}
		// Reconstruct on restart; origins are not trusted from log text.
		if f, err := os.Open(a.journalPath(e.Time)); err == nil {
			scan := bufio.NewScanner(f)
			scan.Buffer(make([]byte, 65536), 262144)
			for scan.Scan() {
				var ev Event
				if json.Unmarshal(scan.Bytes(), &ev) == nil {
					a.capacity.Bytes[ev.SenderIP] += int64(len(scan.Bytes()) + 1)
				}
			}
			f.Close()
		}
	}
	limit := a.cfg.MaxDailyMB
	if limit == 0 {
		limit = 256
	}
	totalLimit := int64(limit) << 20
	critical := a.classifiedEvent(e).Level >= 12
	normalLimit := totalLimit * 80 / 100
	st, err := os.Stat(a.journalPath(e.Time))
	size := int64(0)
	if err == nil {
		size = st.Size()
	}
	quota := normalLimit / 2
	origins := len(a.cfg.Devices) + len(a.state.Receivers.Sources)
	if origins > 2 {
		quota = normalLimit / int64(origins)
	}
	if size >= normalLimit*80/100 && !a.capacity.Warned["global"] {
		a.capacity.Warned["global"] = true
		a.capacitySignal("80% da capacidade normal atingida; reserva crítica preservada", e, false)
	}
	if critical {
		return size+bytes <= totalLimit
	}
	if a.capacity.Bytes[e.SenderIP] >= quota*80/100 && !a.capacity.Warned[e.SenderIP] {
		a.capacity.Warned[e.SenderIP] = true
		a.capacitySignal("80% da cota por origem atingida", e, false)
	}
	return size+bytes <= normalLimit && a.capacity.Bytes[e.SenderIP]+bytes <= quota
}
func (a *App) spoolEvent(e Event) bool {
	dir := filepath.Join(a.cfg.DataDir, "spool")
	if err := os.MkdirAll(dir, 0700); err != nil {
		a.capacitySignal("spool indisponível", e, true)
		return false
	}
	if !a.spoolInitialized {
		entries, err := os.ReadDir(dir)
		if err != nil {
			a.capacitySignal("spool indisponível", e, true)
			return false
		}
		a.spoolOrigins = map[string]int{}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			a.spoolRecords++
			a.spoolBytes += info.Size()
			if len(entry.Name()) >= 16 {
				a.spoolOrigins[entry.Name()[:16]]++
			}
		}
		a.spoolInitialized = true
	}
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		a.capacitySignal("spool: serialização inválida", e, true)
		return false
	}
	prefix := secretDigest(e.SenderIP)[:16]
	path := filepath.Join(dir, prefix+"-"+secretDigest(e.ID)+".json")
	previousSize := int64(0)
	existing := false
	if info, err := os.Stat(path); err == nil {
		previousSize = info.Size()
		existing = true
	}
	capRecords := spoolMaxRecords
	ownLimit := 640
	byteLimit := spoolMaxBytes
	if a.classifiedEvent(e).Level < 12 {
		capRecords = spoolMaxRecords * 80 / 100
		ownLimit = 512
		byteLimit = spoolMaxBytes * 80 / 100
	}
	if (!existing && (a.spoolRecords >= capRecords || a.spoolOrigins[prefix] >= ownLimit)) || a.spoolBytes-previousSize+int64(len(raw)) > byteLimit {
		a.capacitySignal("spool limitado saturado", e, true)
		return false
	}
	if err = atomicJSON(path, e); err != nil {
		a.capacitySignal("falha ao persistir spool", e, true)
		return false
	}
	if !existing {
		a.spoolRecords++
		a.spoolOrigins[prefix]++
	}
	a.spoolBytes += int64(len(raw)) - previousSize
	a.capacitySignal("evento preservado no spool durável", e, false)
	return true
}
func (a *App) spoolRemoved(name string, size int64) {
	if !a.spoolInitialized {
		return
	}
	a.spoolRecords = max(0, a.spoolRecords-1)
	a.spoolBytes = max(int64(0), a.spoolBytes-size)
	if len(name) >= 16 {
		prefix := name[:16]
		a.spoolOrigins[prefix] = max(0, a.spoolOrigins[prefix]-1)
	}
}
func (a *App) drainSpoolLocked() {
	dir := filepath.Join(a.cfg.DataDir, "spool")
	entries, _ := os.ReadDir(dir)
	processed := 0
	for _, entry := range entries {
		if processed >= 100 {
			return
		}
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil || len(raw) > 262144 {
			continue
		}
		var e Event
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		if e.Time.Before(time.Now().AddDate(0, 0, -a.cfg.RetentionDays)) {
			a.capacitySignal("spool expirou a retenção sem poder gravar diário", e, true)
			if os.Remove(path) == nil {
				a.spoolRemoved(entry.Name(), int64(len(raw)))
			}
			continue
		}
		if e.ProblemKey != "" {
			e.ProblemKey = ""
			e = a.trackProblemLocked(e)
			if e.ProblemKey != "" {
				if os.Remove(path) == nil {
					a.spoolRemoved(entry.Name(), int64(len(raw)))
				}
				processed++
				continue
			}
		}
		line, _ := json.Marshal(e)
		if !a.journalQuota(e, int64(len(line)+1)) {
			continue
		}
		target := a.journalPath(e.Time)
		if e.ProblemKey != "" {
			target = a.problemJournalPath(e.Time)
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				continue
			}
		}
		f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			continue
		}
		_, err = f.Write(append(line, '\n'))
		if err == nil {
			err = f.Sync()
		}
		ce := f.Close()
		if err == nil {
			err = ce
		}
		if err != nil {
			continue
		}
		a.capacity.Bytes[e.SenderIP] += int64(len(line) + 1)
		// Journal uses stable event IDs; a crash before remove may replay an ID.
		if err = os.Remove(path); err != nil {
			log.Printf("SIEM_CAPACITY spool_remove_failed=%q", fmt.Sprint(err))
		} else {
			a.spoolRemoved(entry.Name(), int64(len(raw)))
		}
		processed++
	}
}
