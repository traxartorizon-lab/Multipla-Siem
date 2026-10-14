package main

import (
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type tenantScope struct {
	Global  bool
	Clients map[string]bool
}

func (s tenantScope) event(e Event) bool { return s.Global || (e.Tenant != "" && s.Clients[e.Tenant]) }
func (s tenantScope) notification(n SystemNotification) bool {
	return s.Global || (n.Tenant != "" && s.Clients[n.Tenant])
}
func (a *App) scopeLocked(email string) tenantScope {
	account, exists := a.state.Accounts[strings.ToLower(email)]
	// Existing operator accounts retain their internal scope until explicitly assigned.
	global := !exists || (account.GlobalAccess == nil && len(account.Clients) == 0) || (account.GlobalAccess != nil && *account.GlobalAccess)
	s := tenantScope{Global: global, Clients: map[string]bool{}}
	for _, client := range account.Clients {
		s.Clients[client] = true
	}
	return s
}
func (a *App) requestScope(r *http.Request) tenantScope {
	session, ok := a.session(r)
	if !ok {
		return tenantScope{Clients: map[string]bool{}}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.scopeLocked(session.Email)
}
func (a *App) tenantForSenderLocked(ip string) string {
	if _, err := netip.ParseAddr(ip); err != nil {
		return ""
	}
	tenant := ""
	found := false
	for _, d := range a.cfg.Devices {
		if d.IP == ip {
			if found && tenant != d.Client {
				return ""
			}
			found = true
			tenant = d.Client
		}
	}
	for _, source := range a.state.Receivers.Sources {
		d := snmpDevice(source)
		if d.IP == ip {
			if found && tenant != d.Client {
				return ""
			}
			found = true
			tenant = d.Client
		}
	}
	return tenant
}

// Explicit allowlist: new routes cannot accidentally expose global data to scoped accounts.
func tenantRouteSafe(method, path string) bool {
	if strings.HasPrefix(path, "/api/events/") && strings.HasSuffix(path, "/hide") {
		return method == "POST"
	}
	if strings.HasPrefix(path, "/api/problem-devices/") {
		return method == "GET" || method == "DELETE"
	}
	if strings.HasPrefix(path, "/api/desktop/grants") {
		return true
	}
	if strings.HasPrefix(path, "/api/notifications/") && strings.HasSuffix(path, "/read") {
		return method == "POST"
	}
	if path == "/api/devices/metrics-key" {
		return method == "POST"
	}
	switch path {
	case "/auth/logout", "/api/activity", "/api/notifications/clear", "/api/assistant/plan", "/api/assistant/query":
		return method == "POST"
	case "/api/export", "/api/devices/collector-package", "/api/snapshot", "/api/notifications", "/api/events/history", "/api/reports", "/api/events/critical-ips", "/api/devices/metrics", "/api/problem-devices":
		return method == "GET"
	case "/api/dashboard/layout":
		return method == "PUT"
	}
	return false
}
func (a *App) scopedSnapshotLocked(w http.ResponseWriter, s Session, scope tenantScope) {
	events := []Event{}
	critical := []Event{}
	devices := []Device{}
	lastSeen := map[string]time.Time{}
	index := map[string]string{}
	for _, d := range a.cfg.Devices {
		if scope.Clients[d.Client] {
			devices = append(devices, d)
			index[d.Name] = d.Client
			index[d.IP] = d.Client
			lastSeen[d.Name] = a.lastSeen[d.Name]
		}
	}
	for i := len(a.events) - 1; i >= 0; i-- {
		e := a.events[i]
		if !scope.event(e) || a.eventHiddenLocked(e) {
			continue
		}
		e = a.classifiedEvent(e)
		if e.Level >= 12 {
			critical = append(critical, e)
		}
		if a.groupLocked(s.Email) != groupAlerts || e.Alert || e.Level >= 12 {
			events = append(events, e)
		}
	}
	writeJSON(w, map[string]any{"version": productVersion(), "role": a.roleLocked(s.Email), "group": a.groupLocked(s.Email), "scoped": true, "email": s.Email, "csrf": s.CSRF, "events": events, "critical_events": critical, "alerts": len(critical), "total": len(events), "config": map[string]any{"devices": devices, "allowed_emails": []string{s.Email}, "auto_block": false}, "event_clients": index, "last_seen": lastSeen, "rules": []Rule{}, "audit": []Audit{}, "blocks": []Block{}, "preferences": a.preferences(s.Email)})
}
