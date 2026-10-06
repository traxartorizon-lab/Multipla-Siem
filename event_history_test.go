package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestHistoryIncludes24HoursAcrossDaysWithoutMemory(t *testing.T) {
	a := testApp(t)
	now := time.Now()
	for _, age := range []time.Duration{time.Hour, 23 * time.Hour, 25 * time.Hour} {
		if !a.appendEvent(Event{ID: token(), Time: now.Add(-age), Message: "history"}) {
			t.Fatal("journal")
		}
	}
	a.events = nil
	r := httptest.NewRequest("GET", "/api/events/history", nil)
	events, more, partial, err := a.historyEvents(r, 0, "")
	if err != nil || more || partial || len(events) != 2 {
		t.Fatal(len(events), more, partial, err)
	}
}
