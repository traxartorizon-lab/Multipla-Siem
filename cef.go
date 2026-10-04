package main

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type CEFEvent struct {
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	EventID     string `json:"event_id"`
	Name        string `json:"name"`
	Severity    int    `json:"severity"`
	Category    string `json:"category,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
}

var cefKeys = regexp.MustCompile(`(?:^|\s)([A-Za-z][A-Za-z0-9_]{0,63})=`)

func parseCEF(raw string) (CEFEvent, bool) {
	var event CEFEvent
	if len(raw) > 16384 {
		return event, false
	}
	start := strings.Index(raw, "CEF:")
	if start < 0 || start > 512 {
		return event, false
	}
	parts := []string{}
	var part strings.Builder
	escaped := false
	for _, ch := range raw[start:] {
		if escaped {
			if ch != '|' && ch != '\\' {
				part.WriteRune('\\')
			}
			part.WriteRune(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '|' && len(parts) < 7 {
			parts = append(parts, part.String())
			part.Reset()
			continue
		}
		part.WriteRune(ch)
	}
	if escaped {
		part.WriteByte('\\')
	}
	parts = append(parts, part.String())
	if len(parts) != 8 || (parts[0] != "CEF:0" && parts[0] != "CEF:1") {
		return event, false
	}
	severity, err := strconv.Atoi(parts[6])
	if err != nil {
		if value, ok := map[string]int{"unknown": 0, "low": 2, "medium": 5, "high": 8, "very-high": 10}[strings.ToLower(parts[6])]; ok {
			severity = value
			err = nil
		}
	}
	if err != nil || severity < 0 || severity > 10 || len(parts[5]) > 256 || len(parts[1]) > 128 || len(parts[2]) > 128 || len(parts[4]) > 128 {
		return event, false
	}
	event = CEFEvent{Vendor: parts[1], Product: parts[2], EventID: parts[4], Name: parts[5], Severity: severity}
	matches := cefKeys.FindAllStringSubmatchIndex(parts[7], 128)
	for i, match := range matches {
		end := len(parts[7])
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		key := parts[7][match[2]:match[3]]
		value := strings.TrimSpace(parts[7][match[1]:end])
		switch key {
		case "src", "dst":
			if ip, e := netip.ParseAddr(value); e == nil {
				if key == "src" {
					event.Source = ip.Unmap().String()
				} else {
					event.Destination = ip.Unmap().String()
				}
			}
		case "UNIFIcategory":
			if len(value) <= 80 {
				event.Category = value
			}
		}
	}
	return event, true
}

func cefAlert(event CEFEvent) (string, int) {
	name := strings.ToLower(event.Name)
	if event.Severity >= 7 {
		return "CEF: " + event.Name, 12
	}
	if strings.EqualFold(event.Vendor, "Ubiquiti") {
		if event.Category == "Security" && (strings.Contains(name, "threat") || strings.Contains(name, "honeypot") || strings.Contains(name, "intrusion")) {
			return "UniFi: " + event.Name, 11
		}
		if strings.Contains(name, "admin") && (strings.Contains(name, "fail") || strings.Contains(name, "unauthorized")) {
			return "UniFi: falha de acesso administrativo", 10
		}
		if strings.Contains(name, "device offline") || strings.Contains(name, "wan failover") || strings.Contains(name, "power insufficient") || strings.Contains(name, "insufficient poe") {
			return "UniFi: " + event.Name, 9
		}
	}
	return "", 0
}
