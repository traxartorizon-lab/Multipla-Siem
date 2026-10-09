package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestFocusSSHTypeExcludesUnrelatedLogsAndIncludesOtherIPs(t *testing.T) {
	a := testApp(t)
	now := time.Now().UTC().Add(-time.Second)
	seed := Event{ID: "trigger", Time: now, Device: "Firewall", Kind: "pfsense", Message: `<38>1 2026-10-09T12:00:00Z fw sshd-session 1 - - Invalid user alice from 192.0.2.10 port 44`, Rule: "pfSense · Atividade SSH suspeita", Level: 12}
	if !a.appendEvent(seed) {
		t.Fatal("journal")
	}
	for _, e := range []Event{
		{ID: "other-ip", Time: now, Device: "Firewall", Message: "sshd: Invalid user bob from 192.0.2.20 port 55"},
		{ID: "other-type", Time: now, Device: "Firewall", Message: "sshd: Failed password for invalid user bob from 192.0.2.20 port 55"},
		{ID: "other-device", Time: now, Device: "Other", Message: "sshd: Invalid user bob from 192.0.2.20 port 55"},
		{ID: "unrelated", Time: now, Device: "Firewall", Message: "filterlog traffic accepted"},
	} {
		if !a.appendEvent(e) {
			t.Fatal("journal")
		}
	}
	a.events = nil // Focus must survive eviction from live memory through notification metadata.
	events, more, partial, err := a.historyEvents(httptest.NewRequest("GET", "/api/events/history?focus=trigger", nil), 0, "")
	if err != nil || more || partial || len(events) != 2 {
		t.Fatal(len(events), more, partial, err)
	}
	for _, e := range events {
		if e.ID != "trigger" && e.ID != "other-ip" {
			t.Fatal("unrelated log included", e.ID)
		}
	}
}

func TestFocusGlobalBurstUsesSameIPAcrossDevicesAndStrictWindow(t *testing.T) {
	at := time.Now().UTC()
	f := focusForEvent(Event{Time: at, Detector: "ssh-login-burst", SourceIP: "192.0.2.10"})
	e := Event{Time: at.Add(-30 * time.Second), Device: "Other", Message: "sshd: Failed password for root from 192.0.2.10 port 44"}
	if !f.matches(e) {
		t.Fatal("cross-device failure omitted")
	}
	e.Time = at.Add(-time.Minute)
	if f.matches(e) {
		t.Fatal("expired failure included")
	}
	e.Time = at
	e.Message = "sshd: Invalid user root from 192.0.2.10 port 44"
	if f.matches(e) {
		t.Fatal("paired record counted")
	}
	e.Message = "sshd: Failed password for root from 192.0.2.20 port 44"
	if f.matches(e) {
		t.Fatal("different IP included")
	}
}

func TestLegacyNotificationFocusResolvesOriginalJournalAndRejectsMissing(t *testing.T) {
	a := testApp(t)
	e := Event{ID: "legacy", Time: time.Now().UTC().Add(-48 * time.Hour), Device: "Firewall", Message: "disk error"}
	if !a.appendEvent(e) {
		t.Fatal("journal")
	}
	a.events = nil
	r := httptest.NewRequest("GET", "/api/events/history", nil)
	f, err := a.resolveEventFocus(r, e.ID)
	if err != nil || f.Pattern != descriptionKey(e.Message) {
		t.Fatal(f, err)
	}
	if _, err = a.resolveEventFocus(r, "missing"); err == nil {
		t.Fatal("missing anchor fell back to live feed")
	}
}
