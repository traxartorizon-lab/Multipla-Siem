package main

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// Compact trigger metadata survives eviction from the live event window.
type EventFocus struct {
	Time     time.Time `json:"time"`
	Device   string    `json:"device"`
	Rule     string    `json:"rule"`
	Detector string    `json:"detector"`
	Pattern  string    `json:"pattern"`
	SSHType  string    `json:"ssh_type,omitempty"`
	SourceIP string    `json:"source_ip,omitempty"`
}

func sshFocusType(message string) string {
	if pfsenseSSHSource(message) == "" {
		return ""
	}
	body := criticalDescription(message)
	if m := pfSSHProgram.FindStringSubmatch(message); len(m) == 2 {
		body = m[1]
	}
	body = strings.ToLower(body)
	for _, prefix := range []string{"failed password for", "invalid user", "attack from", "blocking"} {
		if strings.HasPrefix(body, prefix) {
			return prefix
		}
	}
	return ""
}
func focusForEvent(e Event) EventFocus {
	if _, raw, ok := strings.Cut(e.Message, " | Evidência: "); ok {
		e.Message = raw
	}
	return EventFocus{Time: e.Time, Device: e.Device, Rule: e.Rule, Detector: e.Detector, Pattern: descriptionKey(e.Message), SSHType: sshFocusType(e.Message), SourceIP: e.SourceIP}
}
func (f EventFocus) matches(e Event) bool {
	if f.Detector == "ssh-login-burst" {
		return !e.Alert && e.Time.After(f.Time.Add(-time.Minute)) && sshFailedPassword.MatchString(e.Message) && pfsenseSSHSource(e.Message) == f.SourceIP
	}
	if e.Device != f.Device {
		return false
	}
	if f.SSHType != "" {
		return !e.Alert && sshFocusType(e.Message) == f.SSHType
	}
	if f.Pattern == descriptionKey(e.Message) {
		return true
	}
	return f.Rule != "" && e.Alert && e.Rule == f.Rule && e.Detector == f.Detector
}
func (a *App) resolveEventFocus(r *http.Request, id string) (EventFocus, error) {
	a.mu.Lock()
	for _, n := range a.state.Notifications {
		if n.EventID == id && n.Focus != nil {
			f := *n.Focus
			a.mu.Unlock()
			return f, nil
		}
	}
	for _, e := range a.events {
		if e.ID == id {
			f := focusForEvent(e)
			a.mu.Unlock()
			return f, nil
		}
	}
	a.mu.Unlock()
	// Older notifications predate persisted focus metadata. Resolve their original log.
	query := r.Clone(r.Context())
	u := *r.URL
	query.URL = &u
	p := u.Query()
	p.Del("focus")
	p.Set("from", time.Now().UTC().Add(-31*24*time.Hour).Format(time.RFC3339Nano))
	p.Del("to")
	query.URL.RawQuery = p.Encode()
	events, _, partial, err := a.historyEvents(query, 0, id)
	if err != nil {
		return EventFocus{}, err
	}
	if len(events) == 0 {
		if partial {
			return EventFocus{}, errors.New("Não foi possível localizar o gatilho dentro do limite de leitura do histórico")
		}
		return EventFocus{}, errors.New("Registro do gatilho indisponível ou fora da retenção")
	}
	return focusForEvent(events[0]), nil
}
