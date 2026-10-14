package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type ProblemGroup struct {
	Key         string    `json:"key"`
	Tenant      string    `json:"tenant"`
	Device      string    `json:"device"`
	SenderIP    string    `json:"sender_ip"`
	Description string    `json:"description"`
	Count       int64     `json:"count"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
	Until       time.Time `json:"until,omitempty"`
	Permanent   bool      `json:"permanent"`
	Automatic   bool      `json:"automatic"`
	Latest      Event     `json:"latest"`
}

func problemKey(e Event) string {
	return secretDigest(e.Tenant + "\x00" + e.SenderIP + "\x00" + e.Device + "\x00" + descriptionKey(e.Message))
}
func problemActive(g ProblemGroup) bool {
	return g.Permanent || (!g.Until.IsZero() && time.Now().Before(g.Until)) || g.Automatic
}
func (a *App) eventHiddenLocked(e Event) bool {
	g, ok := a.state.ProblemGroups[problemKey(e)]
	if e.ProblemKey != "" {
		g, ok = a.state.ProblemGroups[e.ProblemKey]
	}
	return ok && problemActive(g)
}
func (a *App) trackProblemLocked(e Event) Event {
	key := problemKey(e)
	g, exists := a.state.ProblemGroups[key]
	if !exists {
		if a.state.ProblemAutomatic != nil && !*a.state.ProblemAutomatic {
			return e
		}
		counterKey := secretDigest(e.SenderIP)[:16] + ":" + key
		if a.problemCounters == nil {
			a.problemCounters = map[string]bucket{}
			a.problemOriginCounters = map[string]int{}
		}
		b, known := a.problemCounters[counterKey]
		if !known {
			if len(a.problemCounters) >= 2048 || a.problemOriginCounters[e.SenderIP] >= 256 {
				return e
			}
			a.problemOriginCounters[e.SenderIP]++
		}
		now := time.Now()
		if now.Sub(b.Last) > time.Minute {
			b.Times = nil
		}
		b.Last = now
		if len(b.Times) < 3 {
			b.Times = append(b.Times, now)
		}
		a.problemCounters[counterKey] = b
		if len(b.Times) < 3 || len(a.state.ProblemGroups) >= 128 {
			return e
		}
		g = ProblemGroup{Key: key, Tenant: e.Tenant, Device: e.Device, SenderIP: e.SenderIP, Description: criticalDescription(e.Message), First: e.Time, Automatic: true}
	}
	if !problemActive(g) {
		return e
	}
	g.Count++
	g.Last = e.Time
	g.Latest = e
	e.ProblemKey = key
	if a.state.ProblemGroups == nil {
		a.state.ProblemGroups = map[string]ProblemGroup{}
	}
	a.state.ProblemGroups[key] = g
	a.notificationDirty = true
	return e
}
func (a *App) problemJournalPath(t time.Time) string {
	return filepath.Join(a.cfg.DataDir, "problems", "events-"+t.UTC().Format("2006-01-02")+".jsonl")
}
func (a *App) appendProblemLocked(e Event) bool {
	e = sanitizeEvent(e)
	e.Diagnosis = localDiagnosis(e)
	raw, err := json.Marshal(e)
	if err != nil {
		return false
	}
	path := a.problemJournalPath(e.Time)
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		a.capacitySignal("arquivo de problemas indisponível", e, true)
		return false
	}
	if st, err := os.Stat(path); err == nil && st.Size()+int64(len(raw)+1) > 16<<20 {
		return a.spoolEvent(e)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		_, err = f.Write(append(raw, '\n'))
		if err == nil && e.Level >= 12 {
			err = f.Sync()
		}
		ce := f.Close()
		if err == nil {
			err = ce
		}
	}
	if err != nil {
		a.capacitySignal("falha ao gravar arquivo de problemas", e, true)
		return false
	}
	a.notifyCriticalEvent(a.classifiedEvent(e))
	a.queueWebhook(a.classifiedEvent(e))
	a.queueN8N(a.classifiedEvent(e))
	if e.Alert && e.Level >= a.cfg.MailMinLevel {
		a.queueMailLocked(e)
	}
	return true
}
func (a *App) registerProblemRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/problem-devices", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		scope := a.scopeLocked(s.Email)
		rows := []ProblemGroup{}
		for _, g := range a.state.ProblemGroups {
			if scope.Global || scope.Clients[g.Tenant] {
				rows = append(rows, g)
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Last.After(rows[j].Last) })
		automatic := a.state.ProblemAutomatic == nil || *a.state.ProblemAutomatic
		writeJSON(w, map[string]any{"groups": rows, "automatic": automatic})
	}))
	mux.HandleFunc("GET /api/problem-devices/events", a.auth(func(w http.ResponseWriter, r *http.Request) {
		events, more, partial, err := a.readHistoryEvents(r, 0, "", false, 100)
		if err != nil {
			http.Error(w, "Falha ao consultar problemas", 503)
			return
		}
		writeJSON(w, map[string]any{"events": events, "more": more, "partial": partial})
	}))
	mux.HandleFunc("PUT /api/problem-devices/settings", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.mu.Lock()
		super := a.groupLocked(s.Email) == groupSuperadmin
		a.mu.Unlock()
		if !super {
			http.Error(w, "Exige Superadmin", 403)
			return
		}
		var body struct {
			Automatic bool `json:"automatic"`
		}
		if !decode(w, r, &body) {
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		old := a.state.ProblemAutomatic
		a.state.ProblemAutomatic = &body.Automatic
		a.audit(s.Email, "agrupamento automático de eventos atualizado")
		if a.persist() != nil {
			a.state.ProblemAutomatic = old
			http.Error(w, "Falha ao salvar", 503)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/events/{id}/hide", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Days      int  `json:"days"`
			Permanent bool `json:"permanent"`
		}
		if !decode(w, r, &body) {
			return
		}
		if !body.Permanent && (body.Days < 1 || body.Days > 3650) {
			http.Error(w, "Informe de 1 a 3650 dias", 400)
			return
		}
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		var seed Event
		scope := a.scopeLocked(s.Email)
		for _, e := range a.events {
			if e.ID == r.PathValue("id") && scope.event(e) {
				seed = e
				break
			}
		}
		if seed.ID == "" {
			http.NotFound(w, r)
			return
		}
		key := problemKey(seed)
		if len(a.state.ProblemGroups) >= 128 {
			if _, ok := a.state.ProblemGroups[key]; !ok {
				http.Error(w, "Limite de grupos", 409)
				return
			}
		}
		if a.state.ProblemGroups == nil {
			a.state.ProblemGroups = map[string]ProblemGroup{}
		}
		old, had := a.state.ProblemGroups[key]
		g := ProblemGroup{Key: key, Tenant: seed.Tenant, Device: seed.Device, SenderIP: seed.SenderIP, Description: criticalDescription(seed.Message), First: seed.Time, Last: seed.Time, Count: 1, Permanent: body.Permanent, Latest: seed}
		if !body.Permanent {
			g.Until = time.Now().AddDate(0, 0, body.Days)
		}
		a.state.ProblemGroups[key] = g
		a.audit(s.Email, "evento movido para dispositivos com problema: "+key)
		if a.persist() != nil {
			if had {
				a.state.ProblemGroups[key] = old
			} else {
				delete(a.state.ProblemGroups, key)
			}
			http.Error(w, "Falha ao salvar", 503)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("DELETE /api/problem-devices/{key}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		key := r.PathValue("key")
		g, ok := a.state.ProblemGroups[key]
		scope := a.scopeLocked(s.Email)
		if !ok || (!scope.Global && !scope.Clients[g.Tenant]) {
			http.NotFound(w, r)
			return
		}
		delete(a.state.ProblemGroups, key)
		counterKey := secretDigest(g.SenderIP)[:16] + ":" + key
		if _, exists := a.problemCounters[counterKey]; exists {
			delete(a.problemCounters, counterKey)
			a.problemOriginCounters[g.SenderIP]--
		}
		a.audit(s.Email, "agrupamento/ocultação encerrado: "+key)
		if a.persist() != nil {
			a.state.ProblemGroups[key] = g
			http.Error(w, "Falha ao salvar", 503)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
