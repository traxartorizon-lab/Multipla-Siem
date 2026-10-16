package main

import (
	"net/http"
	"strings"
)

const (
	groupAlerts         = "alerts"
	groupAdministrative = "administrative"
	groupSuperadmin     = "superadmin"
)

func validAccessGroup(group string) bool {
	return group == groupAlerts || group == groupAdministrative || group == groupSuperadmin
}

// Legacy accounts retain their access until an operator explicitly assigns a group.
func (a *App) groupLocked(email string) string {
	account, exists := a.state.Accounts[strings.ToLower(email)]
	if exists && account.Disabled {
		return "disabled"
	}
	if account.Group != "" && !validAccessGroup(account.Group) {
		return "disabled"
	}
	if strings.EqualFold(email, a.state.LocalAdmin.Email) {
		return groupSuperadmin
	}
	if validAccessGroup(account.Group) {
		return account.Group
	}
	if exists && account.Role != "admin" {
		return "legacy-viewer"
	}
	return groupSuperadmin
}

func groupAllows(group, method, path string) bool {
	if group != "disabled" && strings.HasPrefix(path, "/api/desktop/grants") {
		return true
	}
	if group != "disabled" && strings.HasPrefix(path, "/api/notifications/") && strings.HasSuffix(path, "/read") {
		return method == "POST"
	}
	if group == groupSuperadmin || group == "legacy-viewer" {
		return true
	}
	if group == groupAlerts {
		switch path {
		case "/auth/logout", "/api/activity", "/api/notifications/clear":
			return method == "POST"
		case "/api/snapshot", "/api/notifications", "/api/events/history", "/api/system/health", "/api/problem-devices", "/api/problem-devices/events":
			return method == "GET"
		}
		return false
	}
	if group != groupAdministrative {
		return false
	}
	// Identity, secrets, recovery, host control and interactive shells are restricted.
	for _, prefix := range []string{"/api/accounts", "/api/account/", "/api/google", "/api/settings/google", "/api/preferences", "/api/backup", "/api/drive", "/api/ssh", "/api/server-terminal", "/api/system/reboot", "/api/system/update"} {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

func (a *App) hostSuperadmin(r *http.Request) bool {
	s, ok := a.session(r)
	if !ok {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.groupLocked(s.Email) == groupSuperadmin && a.scopeLocked(s.Email).Global
}
