package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

type CriticalPattern struct {
	Critical bool      `json:"critical"`
	Sound    bool      `json:"sound"`
	Started  time.Time `json:"started"`
	Updated  time.Time `json:"updated"`
	Seed     Event     `json:"seed"`
}
type CriticalClassification struct {
	Critical bool `json:"critical"`
	Sound    bool `json:"sound"`
}

var syslog5424Description = regexp.MustCompile(`^<\d{1,3}>\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?:-|\[[^\]]*\])\s*`)
var syslog3164Description = regexp.MustCompile(`^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+`)
var sshguardPrefix = regexp.MustCompile(`(?i)^sshguard(?:\[\d+\])?:\s*`)
var sshguardAttackIP = regexp.MustCompile(`(?i)Attack from ["']?([0-9a-f:.]+)["']? on service`)

func criticalDescription(message string) string {
	body := syslog5424Description.ReplaceAllString(message, "")
	body = syslog3164Description.ReplaceAllString(body, "")
	if strings.Contains(strings.ToLower(message), "sshguard") {
		body = sshguardPrefix.ReplaceAllString(body, "")
		body = sshguardAttackIP.ReplaceAllString(body, "Attack from {IP} on service")
	}
	return strings.TrimSpace(body)
}

var attackOrigin = regexp.MustCompile(`(?i)\bAttack from\s+["']?([0-9a-f:.]+)["']?(?:\s|$)`)
var invalidUserOrigin = regexp.MustCompile(`(?i)\bInvalid user\s+\S+\s+from\s+([0-9a-f:.]+)(?:\s|$)`)
var guardBlockedOrigin = regexp.MustCompile(`(?i)\bBlocking\s+["']?([0-9a-f:.]+)(?:/(32|128))?["']?(?:\s|$)`)

func securityLogSourceIP(message string) string {
	for _, pattern := range []*regexp.Regexp{attackOrigin, invalidUserOrigin, guardBlockedOrigin} {
		if pattern == guardBlockedOrigin && !strings.Contains(strings.ToLower(message), "sshguard") {
			continue
		}
		match := pattern.FindStringSubmatch(message)
		if len(match) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(match[1])
		if err != nil {
			continue
		}
		if pattern == guardBlockedOrigin && len(match) > 2 && match[2] != "" && ((ip.Is4() && match[2] != "32") || (ip.Is6() && match[2] != "128")) {
			continue
		}
		return ip.Unmap().String()
	}
	return ""
}
func criticalSourceIP(e Event) string {
	if ip := securityLogSourceIP(e.Message); ip != "" {
		return ip
	}
	if ip, err := netip.ParseAddr(e.SourceIP); err == nil {
		return ip.Unmap().String()
	}
	return ""
}

func descriptionKey(message string) string {
	sum := sha256.Sum256([]byte(criticalDescription(message)))
	return hex.EncodeToString(sum[:])
}

// Only response/notification copies are changed; the journal remains evidence.
// Call while holding a.mu.
func (a *App) classifiedEvent(e Event) Event {
	if e.Kind == "pfsense" && pfsenseSSHThreat(e.Message) {
		e.Level = 12
		e.Alert = true
		if e.Rule == "" {
			e.Rule = "pfSense · Atividade SSH suspeita"
		}
	}
	if ip := criticalSourceIP(e); ip != "" {
		e.SourceIP = ip
	}
	if review, ok := a.state.AlertReviews[e.ID]; ok {
		copy := review
		e.Review = &copy
		if review.Status != "false_positive" && review.Level >= 12 {
			e.Level = review.Level
			e.Alert = true
			if e.Rule == "" {
				e.Rule = review.Title
			}
		}
	}
	if policy, ok := a.state.CriticalPatterns[descriptionKey(e.Message)]; ok && (!policy.Critical || e.ID == policy.Seed.ID || !e.Time.Before(policy.Started) || (e.Review != nil && e.Review.Level >= 12)) {
		e.Classification = &CriticalClassification{Critical: policy.Critical, Sound: policy.Sound}
		if policy.Critical {
			e.Level = 15
			e.Alert = true
			if e.Rule == "" {
				e.Rule = "Descrição marcada como crítica"
			}
		} else {
			if e.Level >= 12 {
				e.Level = 11
			}
			e.Diagnosis = nil
			e.ModelDiagnosis = nil
			if e.Review != nil {
				copy := *e.Review
				if copy.Level >= 12 {
					copy.Level = 11
				}
				e.Review = &copy
			}
		}
	}
	if e.Classification == nil || e.Classification.Critical {
		e.Diagnosis = localDiagnosis(e)
	}
	return e
}

func (a *App) criticalDashboardEvents() []Event {
	all := make(map[string]Event)
	for _, e := range a.events {
		all[e.ID] = e
	}
	cutoff := time.Now().AddDate(0, 0, -a.cfg.RetentionDays)
	if a.cfg.RetentionDays <= 0 {
		cutoff = time.Now().AddDate(0, 0, -7)
	}
	for _, p := range a.state.CriticalPatterns {
		if !p.Seed.Time.Before(cutoff) {
			if _, ok := all[p.Seed.ID]; !ok {
				all[p.Seed.ID] = p.Seed
			}
		}
	}
	result := []Event{}
	for _, e := range all {
		e = a.classifiedEvent(e)
		if e.Level >= 12 && (e.Review == nil || e.Review.Status != "false_positive") {
			result = append(result, e)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Time.After(result[j].Time) })
	if len(result) > 8 {
		result = result[:8]
	}
	return result
}

func (a *App) registerCriticalPatternRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/events/critical-ips", a.auth(func(w http.ResponseWriter, r *http.Request) {
		from, to, rangeErr := historyTimeRange(r, time.Now().UTC())
		if rangeErr != nil {
			http.Error(w, rangeErr.Error(), 400)
			return
		}
		q := r.URL.Query()
		q.Set("from", from.Format(time.RFC3339Nano))
		q.Set("to", to.Format(time.RFC3339Nano))
		copyRequest := r.Clone(r.Context())
		copyURL := *r.URL
		copyURL.RawQuery = q.Encode()
		copyRequest.URL = &copyURL
		select {
		case reportSlots <- struct{}{}:
			defer func() { <-reportSlots }()
		default:
			http.Error(w, "Consulta em andamento", 429)
			return
		}
		events, more, partial, err := a.readHistoryEvents(copyRequest, 0, "", true, 10000)
		if err != nil {
			http.Error(w, "Falha ao ler histórico", 500)
			return
		}
		ips := aggregateCriticalIPs(events)
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Query().Get("download") == "1" {
			if partial || more {
				http.Error(w, "Consulta parcial: reduza o intervalo antes de baixar a lista", 422)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="ips-eventos-criticos.txt"`)
			for _, row := range ips {
				w.Write([]byte(row.IP + "\n"))
			}
			return
		}

		writeJSON(w, map[string]any{"ips": ips, "partial": partial || more, "from": from, "to": to})
	}))

	mux.HandleFunc("PUT /api/events/{id}/critical-pattern", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Critical *bool `json:"critical"`
			Sound    *bool `json:"sound"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.Critical == nil || input.Sound == nil || (!*input.Critical && *input.Sound) {
			http.Error(w, "Informe classificação e som válidos", 400)
			return
		}
		session, _ := a.session(r)
		id := r.PathValue("id")
		a.mu.Lock()
		var event Event
		for _, e := range a.events {
			if e.ID == id {
				event = e
				break
			}
		}
		if event.ID == "" {
			for _, p := range a.state.CriticalPatterns {
				if p.Seed.ID == id {
					event = p.Seed
					break
				}
			}
		}
		a.mu.Unlock()
		if event.ID == "" {
			history, _, _, err := a.historyEvents(r, 0, id)
			if err == nil && len(history) == 1 {
				event = history[0]
			}
		}
		if event.ID == "" {
			http.NotFound(w, r)
			return
		}
		if event.Message == "" || len(event.Message) > 16384 {
			http.Error(w, "Descrição vazia ou extensa demais", 400)
			return
		}
		event = sanitizeEvent(event)
		event.Review = nil
		event.Classification = nil
		event.Diagnosis = nil
		event.ModelDiagnosis = nil
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.state.CriticalPatterns == nil {
			a.state.CriticalPatterns = map[string]CriticalPattern{}
		}
		key := descriptionKey(event.Message)
		previous, exists := a.state.CriticalPatterns[key]
		if !exists && len(a.state.CriticalPatterns) >= 128 {
			http.Error(w, "Limite de 128 descrições atingido", 409)
			return
		}
		now := time.Now().UTC()
		policy := CriticalPattern{Critical: *input.Critical, Sound: *input.Sound, Started: now, Updated: now, Seed: event}
		if exists {
			policy.Started = previous.Started
			policy.Seed = event
		}
		oldNotifications := append([]SystemNotification{}, a.state.Notifications...)
		oldDirty := a.notificationDirty
		oldAudit := append([]Audit{}, a.state.Audit...)
		if a.state.AlertReviews == nil {
			a.state.AlertReviews = map[string]AlertReview{}
		}
		oldReview, hadReview := a.state.AlertReviews[id]
		if !hadReview && len(a.state.AlertReviews) >= 2000 {
			http.Error(w, "Limite de avaliações atingido", 409)
			return
		}
		review := oldReview
		if review.Title == "" {
			review.Title = "Descrição crítica"
		}
		review.Level = 15
		review.Status = "open"
		review.Updated = now
		review.Actor = session.Email
		if !policy.Critical {
			review.Level = 11
		}
		a.state.AlertReviews[id] = review
		a.state.CriticalPatterns[key] = policy
		if policy.Critical {
			a.notifyCriticalEvent(a.classifiedEvent(event))
		}
		a.audit(session.Email, "classificação por descrição atualizada: "+key+"; crítico="+boolText(policy.Critical)+"; som="+boolText(policy.Sound))
		if err := a.persist(); err != nil {
			if exists {
				a.state.CriticalPatterns[key] = previous
			} else {
				delete(a.state.CriticalPatterns, key)
			}
			a.state.Audit = oldAudit
			a.state.Notifications = oldNotifications
			a.notificationDirty = oldDirty
			if hadReview {
				a.state.AlertReviews[id] = oldReview
			} else {
				delete(a.state.AlertReviews, id)
			}
			http.Error(w, "Falha ao salvar classificação", 500)
			return
		}
		if policy.Critical {
			a.enqueueLocalAI(event)
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
func boolText(value bool) string {
	if value {
		return "sim"
	}
	return "não"
}

type CriticalIPRow struct {
	IP      string    `json:"ip"`
	Count   int       `json:"count"`
	Last    time.Time `json:"last_seen"`
	Devices []string  `json:"devices"`
}

func aggregateCriticalIPs(events []Event) []CriticalIPRow {
	rows := map[string]*CriticalIPRow{}
	seen := map[string]bool{}
	for _, e := range events {
		id := e.ID
		if e.ParentID != "" {
			id = e.ParentID
		}
		if seen[id] {
			continue
		}
		if securityLogSourceIP(e.Message) == "" && (e.Level < 12 || (e.Review != nil && e.Review.Status == "false_positive")) {
			continue
		}
		ip := criticalSourceIP(e)
		if ip == "" {
			continue
		}
		seen[id] = true
		row := rows[ip]
		if row == nil {
			row = &CriticalIPRow{IP: ip, Devices: []string{}}
			rows[ip] = row
		}
		row.Count++
		if e.Time.After(row.Last) {
			row.Last = e.Time
		}
		exists := false
		for _, d := range row.Devices {
			if d == e.Device {
				exists = true
			}
		}
		if !exists {
			row.Devices = append(row.Devices, e.Device)
		}
	}
	result := []CriticalIPRow{}
	for _, row := range rows {
		sort.Strings(row.Devices)
		result = append(result, *row)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IP < result[j].IP })
	return result
}

func validateCriticalPatterns(policies map[string]CriticalPattern) error {
	if len(policies) > 128 {
		return errors.New("limite de classificações excedido")
	}
	for key, p := range policies {
		if p.Seed.ID == "" || p.Seed.Time.IsZero() || len(p.Seed.Message) > 16384 || criticalDescription(p.Seed.Message) == "" || key != descriptionKey(p.Seed.Message) || p.Started.IsZero() || p.Updated.Before(p.Started) || (!p.Critical && p.Sound) {
			return errors.New("classificação crítica inválida")
		}
	}
	return nil
}
