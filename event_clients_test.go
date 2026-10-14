package main

import (
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestHistoryClientFilterBeforePagination(t *testing.T) {
	a := testApp(t)
	a.cfg.Devices = []Device{{Name: "firewall", IP: "192.0.2.1", Client: "Alpha"}, {Name: "server", Client: "Beta"}}
	for i := 0; i < 110; i++ {
		if !a.appendEvent(Event{ID: token(), Time: time.Now().Add(-time.Minute), Device: "server", Message: "Alpha 192.0.2.50"}) {
			t.Fatal("journal")
		}
	}
	for _, e := range []Event{{ID: "alpha", Device: "firewall"}, {ID: "beta", Device: "server"}, {ID: "unassigned", Device: "unknown"}} {
		e.Time = time.Now().Add(-time.Minute)
		e.Message = "192.0.2.50"
		if !a.appendEvent(e) {
			t.Fatal("journal")
		}
	}
	for _, tc := range []struct{ client, id string }{{"Alpha", "alpha"}, {"~unassigned", "unassigned"}, {"missing", ""}} {
		q := url.Values{"client": {tc.client}, "q": {"192.0.2.50"}}
		events, more, partial, err := a.historyEvents(scopedTestRequest(a,httptest.NewRequest("GET", "/?"+q.Encode(), nil)), 0, "")
		if err != nil || more || partial {
			t.Fatal(err, more, partial)
		}
		if tc.id == "" {
			if len(events) != 0 {
				t.Fatal(events)
			}
		} else if len(events) != 1 || events[0].ID != tc.id {
			t.Fatal(tc, events)
		}
	}
}

func TestEventClientIndexDoesNotMixAmbiguousNames(t *testing.T) {
	a := testApp(t)
	a.cfg.Devices = []Device{{Name: "duplicate", IP: "192.0.2.1", Client: "Alpha"}, {Name: "duplicate", IP: "192.0.2.2", Client: "Beta"}}
	index := a.eventClientIndex()
	if clientForEvent(index, Event{Device: "duplicate", SenderIP: "192.0.2.1"}) != "" {
		t.Fatal("ambiguous device assigned")
	}
	if clientForEvent(index, Event{Device: "unknown", SenderIP: "192.0.2.2"}) != "Beta" {
		t.Fatal("sender mapping")
	}
}

func TestCriticalClientHistoryFiltersBeforePagination(t *testing.T) {
	a := testApp(t)
	a.cfg.Devices = []Device{{Name: "alpha", Client: "Alpha"}, {Name: "beta", Client: "Beta"}}
	for i := 0; i < 110; i++ {
		a.appendEvent(Event{ID: token(), Time: time.Now().Add(-time.Minute), Device: "alpha", Level: 1, Message: "ordinary"})
	}
	for _, e := range []Event{{ID: "critical-alpha", Device: "alpha", Level: 12}, {ID: "alert-alpha", Device: "alpha", Level: 10, Alert: true}, {ID: "critical-beta", Device: "beta", Level: 12}} {
		e.Time = time.Now().Add(-time.Minute)
		a.appendEvent(e)
	}
	events, more, partial, err := a.historyEvents(scopedTestRequest(a,httptest.NewRequest("GET", "/api/events/history?critical=1&client=Alpha", nil)), 0, "")
	if err != nil || more || partial || len(events) != 1 || events[0].ID != "critical-alpha" {
		t.Fatal(events, more, partial, err)
	}
}
