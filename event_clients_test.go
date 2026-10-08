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
		events, more, partial, err := a.historyEvents(httptest.NewRequest("GET", "/?"+q.Encode(), nil), 0, "")
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
