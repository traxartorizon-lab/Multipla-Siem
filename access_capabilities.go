package main

import "strings"

func (a *App) backupPrivilegeLocked(email string) bool {
	if !a.scopeLocked(email).Global {
		return false
	}
	group := a.groupLocked(email)
	if group == groupSuperadmin {
		return true
	}
	if group != groupAdministrative {
		return false
	}
	for _, cap := range a.state.Accounts[strings.ToLower(email)].Capabilities {
		if cap == "backup" {
			return true
		}
	}
	return false
}

func (a *App) capabilityAllows(email, method, path string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.groupLocked(email) != groupAdministrative || !a.scopeLocked(email).Global {
		return false
	}
	required := ""
	switch {
	case strings.HasPrefix(path, "/api/accounts"):
		required = "accounts"
	case strings.HasPrefix(path, "/api/backup") || strings.HasPrefix(path, "/api/drive"):
		required = "backup"
	case strings.HasPrefix(path, "/api/ssh") || strings.HasPrefix(path, "/api/server-terminal"):
		required = "terminal"
	}
	if required == "" {
		return false
	}
	for _, cap := range a.state.Accounts[strings.ToLower(email)].Capabilities {
		if cap == required {
			return true
		}
	}
	return false
}
