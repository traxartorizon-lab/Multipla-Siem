package main

import (
	"regexp"
	"time"
)

const sshInvasionTitle = "POSSIVEL TENTATIVA DE INVASAO"

var sshFailedPassword = regexp.MustCompile(`(?i)\bFailed password for (?:invalid user )?\S+ from [0-9a-f:.]+\b`)

// Ten failed-password records across all syslog devices, never double-count Invalid user.
// Caller holds a.mu; this detector only alerts and never blocks.
func (a *App) evaluateGlobalSSH(ev Event, raw string) {
	if ev.Protocol != "syslog" || ev.Kind == "snmp" || ev.Kind == "webhook" || !sshFailedPassword.MatchString(raw) {
		return
	}
	ip := pfsenseSSHSource(raw)
	if ip == "" {
		return
	}
	key := "global-ssh-login|" + ip
	b, known := a.counters[key]
	if !known && len(a.counters) >= 10000 {
		return
	}
	cut := ev.Time.Add(-time.Minute)
	times := []time.Time{}
	for _, at := range b.Times {
		if at.After(cut) {
			times = append(times, at)
		}
	}
	if len(times) < 10 {
		times = append(times, ev.Time)
	}
	b.Times = times
	if len(times) >= 10 && (b.Last.IsZero() || !b.Last.After(cut)) {
		alert := ev
		alert.ID = token()
		alert.ParentID = ev.ID
		alert.SourceIP = ip
		alert.Alert = true
		alert.Level = 15
		alert.Rule = sshInvasionTitle
		alert.Detector = "ssh-login-burst"
		if a.appendEvent(alert) {
			b.Last = ev.Time
		}
	}
	a.counters[key] = b
}
