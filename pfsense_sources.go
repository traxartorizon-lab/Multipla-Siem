package main

import (
	"net/netip"
	"regexp"
	"strings"
)

var pfSSHProgram = regexp.MustCompile(`(?i)\b(?:sshd|sshd-session|sshguard)(?:\[[0-9]+\])?:\s*(.*)$`)
var pfSSH5424Program = regexp.MustCompile(`(?i)^<\d{1,3}>\d+\s+\S+\s+\S+\s+(sshd|sshd-session|sshguard)\s+\S+\s+\S+\s+(?:-|\[[^\]]*\])\s+(.*)$`)

var pfSSHSource = regexp.MustCompile(`(?i)(?:attack from|blocking|connection closed by invalid user|from)\s*["']?([0-9a-f:.]+)(?:/(32|128))?(?:["' ]|$)`)

func pfsenseSSHSource(raw string) string {
	program := pfSSHProgram.FindStringSubmatch(raw)
	if len(program) < 2 {
		if match := pfSSH5424Program.FindStringSubmatch(raw); len(match) == 3 {
			program = []string{match[0], match[2]}
		}
	}
	if len(program) < 2 {
		return ""
	}
	matches := pfSSHSource.FindStringSubmatch(program[1])
	if len(matches) < 2 {
		return ""
	}
	ip, err := netip.ParseAddr(strings.TrimRight(matches[1], "."))
	if err != nil {
		return ""
	}
	if len(matches) > 2 && matches[2] != "" && ((ip.Is4() && matches[2] != "32") || (ip.Is6() && matches[2] != "128")) {
		return ""
	}
	return ip.Unmap().String()
}
func pfsenseGuardRule() Rule {
	return Rule{"pfsense-sshguard", "pfSense · Tentativas SSH repetidas do mesmo IP", "pfsense", `(?i)\b(?:sshd|sshd-session)(?:\[[0-9]+\])?:\s*(?:Invalid user\s|Failed password for invalid user\s)`, 5, 60, 12, true, true}
}

// Recognize security-specific SSH records without initiating a firewall action.
var pfSSHThreat = regexp.MustCompile(`(?i)^(?:Failed password for invalid user\s|Invalid user\s|Attack from ["']?[0-9a-f:.]+["']? on service SSH\b|Blocking ["']?[0-9a-f:./]+["']? for \d+ secs)`)

func pfsenseSSHThreat(raw string) bool {
	body := pfSSHProgram.FindStringSubmatch(raw)
	if len(body) < 2 {
		if match := pfSSH5424Program.FindStringSubmatch(raw); len(match) == 3 {
			body = []string{match[0], match[2]}
		}
	}
	return len(body) == 2 && pfsenseSSHSource(raw) != "" && pfSSHThreat.MatchString(body[1])
}
