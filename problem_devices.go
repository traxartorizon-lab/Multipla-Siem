package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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
	Day         string    `json:"day,omitempty"`
	Suppressed  int64     `json:"suppressed"`
	Latest      Event     `json:"latest"`
}

// Only transport timestamps and process IDs are removed. IPs, ports, failure
// values, severity, protocol and message content remain part of the identity.
var repeatSyslogTime = regexp.MustCompile(`^(<\d{1,3}>)?(?:[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) +`)
var repeatRFC5424Time = regexp.MustCompile(`^(<\d{1,3}>\d{1,3} )\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}) `)
var repeatPID = regexp.MustCompile(`(^| )([a-zA-Z0-9_.-]+)\[\d+\]:`)

func repeatMessage(s string) string {
	s = repeatRFC5424Time.ReplaceAllString(strings.TrimSpace(s), "${1}- ")
	s = repeatSyslogTime.ReplaceAllString(strings.TrimSpace(s), "$1")
	return repeatPID.ReplaceAllString(s, "${1}${2}:")
}
func shortRepeatDescription(s string) string {
	s = repeatMessage(s)
	r := []rune(s)
	if len(r) > 240 {
		return string(r[:240]) + "…"
	}
	return s
}
func problemKey(e Event) string {
	return secretDigest(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%t\x00%s", e.Tenant, e.SenderIP, e.Device, e.SourceIP, e.Kind, e.Protocol, e.Detector, e.Level, e.Alert, e.Rule+"\x00"+repeatMessage(e.Message)))
}
func problemActive(g ProblemGroup) bool {
	return g.Permanent || (!g.Until.IsZero() && time.Now().Before(g.Until)) || (g.Automatic && (g.Day == "" || g.Day == time.Now().UTC().Format("2006-01-02")))
}
func (a *App) eventHiddenLocked(e Event) bool {
	g, ok := a.state.ProblemGroups[problemKey(e)]
	if e.ProblemKey != "" {
		g, ok = a.state.ProblemGroups[e.ProblemKey]
	}
	return ok && problemActive(g) && (!g.Automatic || g.Day == "" || g.Day == e.Time.UTC().Format("2006-01-02"))
}

const repeatGroupLimit = 256
const repeatTenantLimit = 64

type repeatWindow struct {
	Sequence int64        `json:"sequence"`
	Group    ProblemGroup `json:"group"`
	Events   []Event      `json:"events"`
}

func (a *App) repeatPath(key string) string {
	return filepath.Join(a.cfg.DataDir, "problems", "windows", key+".json")
}

type repeatSlot struct {
	Count int64  `json:"count"`
	Day   string `json:"day"`
	Event Event  `json:"event"`
}

func (a *App) repeatSlotPath(key string, count int64) string {
	return filepath.Join(a.cfg.DataDir, "problems", "windows", fmt.Sprintf("%s-slot-%02d.json", key, count%21))
}
func (a *App) saveRepeatWindow(w repeatWindow, e Event) error {
	// 21 slots: the staging slot is outside the previous committed 20. A crash
	// before committing metadata preserves the entire previously committed ring.
	if err := atomicJSON(a.repeatSlotPath(w.Group.Key, w.Sequence), repeatSlot{w.Sequence, w.Group.Day, sanitizeEvent(e)}); err != nil {
		return err
	}
	metadata := w
	metadata.Events = nil
	metadata.Group.Latest = Event{}
	return atomicJSON(a.repeatPath(w.Group.Key), metadata)
}
func (a *App) removeRepeatWindow(key string) error {
	if err := os.Remove(a.repeatPath(key)); err != nil && !os.IsNotExist(err) {
		return err
	}
	for i := int64(0); i < 21; i++ {
		if err := os.Remove(a.repeatSlotPath(key, i)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
func (a *App) pruneRepeatWindowsLocked(now time.Time) {
	for key, w := range a.repeatWindows {
		if w.Group.Last.Before(now.AddDate(0, 0, -a.cfg.RetentionDays)) {
			if a.removeRepeatWindow(key) == nil {
				delete(a.repeatWindows, key)
				if a.state.ProblemGroups[key].Automatic {
					delete(a.state.ProblemGroups, key)
				}
			} else {
				a.capacitySignal("falha ao expirar janela de repetição", w.Group.Latest, false)
			}
		}
	}
}
func (a *App) loadRepeatWindows() error {
	a.repeatWindows = map[string]repeatWindow{}
	if a.state.ProblemGroups == nil {
		a.state.ProblemGroups = map[string]ProblemGroup{}
	}
	for k, g := range a.state.ProblemGroups {
		if g.Automatic {
			delete(a.state.ProblemGroups, k)
		}
	}
	entries, err := os.ReadDir(filepath.Join(a.cfg.DataDir, "problems", "windows"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if a.state.ProblemGroups == nil {
		a.state.ProblemGroups = map[string]ProblemGroup{}
	}
	// Migrate the former 3/minute automatic grouping. Manual hides remain valid.
	for k, g := range a.state.ProblemGroups {
		if g.Automatic {
			delete(a.state.ProblemGroups, k)
		}
	}
	for _, entry := range entries {
		if entry.IsDir() || !regexp.MustCompile(`^[a-f0-9]{64}\.json$`).MatchString(entry.Name()) {
			continue
		}
		path := filepath.Join(a.cfg.DataDir, "problems", "windows", entry.Name())
		st, err := entry.Info()
		if err != nil {
			return err
		}
		if st.Size() > 32<<10 {
			return fmt.Errorf("janela de repetição excede limite")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var window repeatWindow
		if json.Unmarshal(raw, &window) != nil || window.Group.Count < 1 || window.Sequence < window.Group.Count || window.Group.Day == "" || len(window.Events) > 0 || window.Group.Key+".json" != entry.Name() || len(a.repeatWindows) >= repeatGroupLimit {
			return fmt.Errorf("janela de repetição inválida")
		}
		if window.Group.Last.Before(time.Now().AddDate(0, 0, -a.cfg.RetentionDays)) {
			if err := a.removeRepeatWindow(window.Group.Key); err != nil {
				return err
			}
			continue
		}
		for seq := window.Sequence - min(window.Group.Count, 20) + 1; seq <= window.Sequence; seq++ {
			slotPath := a.repeatSlotPath(window.Group.Key, seq)
			info, err := os.Stat(slotPath)
			if err != nil || info.Size() > 128<<10 {
				return fmt.Errorf("slot de repetição indisponível")
			}
			b, err := os.ReadFile(slotPath)
			var slot repeatSlot
			if err != nil || json.Unmarshal(b, &slot) != nil || slot.Count != seq || slot.Day != window.Group.Day {
				return fmt.Errorf("slot de repetição inválido")
			}
			window.Events = append(window.Events, slot.Event)
		}
		window.Group.Latest = window.Events[len(window.Events)-1]
		a.repeatWindows[window.Group.Key] = window
		if window.Group.Count >= 20 {
			if old, ok := a.state.ProblemGroups[window.Group.Key]; !ok || old.Automatic {
				a.state.ProblemGroups[window.Group.Key] = window.Group
			}
		}
	}
	return nil
}
func (a *App) trackProblemLocked(e Event) Event {
	// Called exactly once per original receipt. Derived alerts inherit ProblemKey.
	if e.ParentID != "" {
		return e
	}
	key := problemKey(e)
	if _, ok := a.state.ProblemGroups[key]; !ok {
		for k, g := range a.state.ProblemGroups {
			if !g.Automatic && problemActive(g) && problemKey(g.Latest) == key {
				g.Key = key
				a.state.ProblemGroups[key] = g
				delete(a.state.ProblemGroups, k)
				break
			}
		}
	}
	day := e.Time.UTC().Format("2006-01-02")
	manual, hidden := a.state.ProblemGroups[key]
	hidden = hidden && !manual.Automatic && problemActive(manual)
	if existing, ok := a.state.ProblemGroups[key]; ok && !existing.Automatic && !problemActive(existing) && existing.Day == day {
		return e
	}
	if !hidden && a.state.ProblemAutomatic != nil && !*a.state.ProblemAutomatic {
		return e
	}
	if a.repeatWindows == nil {
		a.repeatWindows = map[string]repeatWindow{}
	}
	old, known := a.repeatWindows[key]
	if !known {
		tenantCount := 0
		for k, w := range a.repeatWindows {
			if w.Group.Last.Before(e.Time.AddDate(0, 0, -a.cfg.RetentionDays)) {
				if a.removeRepeatWindow(k) == nil {
					delete(a.repeatWindows, k)
					if a.state.ProblemGroups[k].Automatic {
						delete(a.state.ProblemGroups, k)
					}
				}
				continue
			}
			if w.Group.Tenant == e.Tenant {
				tenantCount++
			}
		}
		if len(a.repeatWindows) >= repeatGroupLimit || tenantCount >= repeatTenantLimit {
			a.capacitySignal("limite de grupos de repetição; registro global preservado", e, false)
			return e
		}
	}
	window := old
	if window.Group.Day != day {
		window = repeatWindow{Sequence: old.Sequence, Group: ProblemGroup{Key: key, Tenant: e.Tenant, Device: e.Device, SenderIP: e.SenderIP, Description: shortRepeatDescription(e.Message), First: e.Time, Day: day, Automatic: true}}
	}
	window.Sequence++
	window.Group.Count++
	window.Group.Last = e.Time
	window.Group.Latest = e
	if window.Group.Count >= 20 || hidden {
		window.Group.Suppressed++
	}
	window.Events = append(append([]Event(nil), window.Events...), sanitizeEvent(e))
	if len(window.Events) > 20 {
		window.Events = window.Events[len(window.Events)-20:]
	}
	if st, err := os.Stat(a.cfg.DataDir); err != nil || !st.IsDir() {
		a.capacitySignal("diretório da coleta indisponível; tentando registro global", e, false)
		return e
	}
	if err := os.MkdirAll(filepath.Dir(a.repeatPath(key)), 0700); err != nil {
		a.capacitySignal("janela indisponível; registro global preservado", e, false)
		return e
	}
	if err := a.saveRepeatWindow(window, e); err != nil {
		a.capacitySignal("falha na janela; registro global preservado", e, false)
		return e
	}
	a.repeatWindows[key] = window
	if window.Group.Count >= 20 || hidden {
		if a.state.ProblemGroups == nil {
			a.state.ProblemGroups = map[string]ProblemGroup{}
		}
		if hidden {
			manual.Count = window.Group.Count
			manual.Last = e.Time
			manual.Latest = e
			manual.Day = day
			manual.Suppressed = window.Group.Suppressed
			a.state.ProblemGroups[key] = manual
		} else {
			a.state.ProblemGroups[key] = window.Group
		}
		e.ProblemKey = key
		a.notificationDirty = true
	} else if g, ok := a.state.ProblemGroups[key]; ok && g.Automatic {
		delete(a.state.ProblemGroups, key)
	}
	return e
}

// Kept solely for legacy archive retention. New receipts never append here.
func (a *App) problemJournalPath(t time.Time) string {
	return filepath.Join(a.cfg.DataDir, "problems", "events-"+t.UTC().Format("2006-01-02")+".jsonl")
}
func (a *App) appendProblemLocked(e Event) bool {
	// The original receipt was persisted before suppression. Derived alerts do not
	// consume ring slots or increment counts; their security side effects continue.
	a.lastSeen[e.Device] = e.Time
	a.countReceiptLocked(e)
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
		alertsOnly := a.groupLocked(s.Email) == groupAlerts
		rows := []ProblemGroup{}
		for _, g := range a.state.ProblemGroups {
			if (scope.Global || scope.Clients[g.Tenant]) && problemActive(g) && (!alertsOnly || criticalEvent(a.classifiedEvent(g.Latest))) {
				rows = append(rows, g)
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Last.After(rows[j].Last) })
		automatic := a.state.ProblemAutomatic == nil || *a.state.ProblemAutomatic
		writeJSON(w, map[string]any{"groups": rows, "automatic": automatic})
	}))
	mux.HandleFunc("GET /api/problem-devices/events", a.auth(func(w http.ResponseWriter, r *http.Request) {
		scope := a.requestScope(r)
		key := r.URL.Query().Get("group")
		session, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		alertsOnly := a.groupLocked(session.Email) == groupAlerts
		window, ok := a.repeatWindows[key]
		if !ok || window.Group.Count < 20 && !problemActive(a.state.ProblemGroups[key]) || !scope.Global && !scope.Clients[window.Group.Tenant] {
			http.NotFound(w, r)
			return
		}
		events := []Event{}
		for i := len(window.Events) - 1; i >= 0; i-- {
			e := window.Events[i]
			if scope.event(e) && (!alertsOnly || criticalEvent(a.classifiedEvent(e))) {
				events = append(events, e)
			}
		}
		if r.URL.Query().Get("export") == "1" {
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.Header().Set("Content-Disposition", `attachment; filename="repeticoes.jsonl"`)
			for _, e := range events {
				_ = json.NewEncoder(w).Encode(e)
			}
			return
		}
		writeJSON(w, map[string]any{"events": events, "more": false, "partial": false, "day": window.Group.Day, "count": window.Group.Count})
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
		if seed.ParentID != "" {
			for _, parent := range a.events {
				if parent.ID == seed.ParentID && scope.event(parent) {
					seed = parent
					break
				}
			}
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
		window, known := a.repeatWindows[key]
		if known {
			g.Count = window.Group.Count
			g.First = window.Group.First
			g.Last = window.Group.Last
			g.Day = window.Group.Day
			g.Suppressed = window.Group.Suppressed
			g.Latest = window.Group.Latest
		} else {
			tenantCount := 0
			for _, existing := range a.repeatWindows {
				if existing.Group.Tenant == seed.Tenant {
					tenantCount++
				}
			}
			if len(a.repeatWindows) >= repeatGroupLimit || tenantCount >= repeatTenantLimit {
				http.Error(w, "Limite de janelas; evento global preservado", 409)
				return
			}
			g.Day = seed.Time.UTC().Format("2006-01-02")
			window = repeatWindow{Sequence: 1, Group: g, Events: []Event{sanitizeEvent(seed)}}
			if err := os.MkdirAll(filepath.Dir(a.repeatPath(key)), 0700); err != nil {
				http.Error(w, "Falha ao preparar janela; evento global preservado", 503)
				return
			}
			if err := a.saveRepeatWindow(window, seed); err != nil {
				_ = a.removeRepeatWindow(key)
				http.Error(w, "Falha ao salvar janela; evento global preservado", 503)
				return
			}
			if a.repeatWindows == nil {
				a.repeatWindows = map[string]repeatWindow{}
			}
			a.repeatWindows[key] = window
		}
		a.state.ProblemGroups[key] = g
		a.audit(s.Email, "evento movido para dispositivos com problema: "+key)
		if a.persist() != nil {
			if !known {
				delete(a.repeatWindows, key)
				_ = a.removeRepeatWindow(key)
			}
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
		oldGroup := g
		scope := a.scopeLocked(s.Email)
		if !ok || (!scope.Global && !scope.Clients[g.Tenant]) {
			http.NotFound(w, r)
			return
		}
		g.Day = time.Now().UTC().Format("2006-01-02")
		g.Automatic = false
		g.Permanent = false
		g.Until = time.Time{}
		a.state.ProblemGroups[key] = g
		counterKey := secretDigest(g.SenderIP)[:16] + ":" + key
		if _, exists := a.problemCounters[counterKey]; exists {
			delete(a.problemCounters, counterKey)
			a.problemOriginCounters[g.SenderIP]--
		}
		a.audit(s.Email, "agrupamento/ocultação encerrado: "+key)
		if a.persist() != nil {
			a.state.ProblemGroups[key] = oldGroup
			http.Error(w, "Falha ao salvar", 503)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
