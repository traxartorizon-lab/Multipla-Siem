package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestRememberRetainsRecentWindowAndDailyTotal(t *testing.T) {
	a := &App{lastSeen: map[string]time.Time{}}
	at := time.Now().UTC()
	for i := 0; i < 5000; i++ {
		a.remember(Event{ID: fmt.Sprint(i), Time: at, Device: "Firewall"})
	}
	if len(a.events) != 2000 || a.events[0].ID != "3000" || a.events[1999].ID != "4999" || a.total != 5000 || !a.lastSeen["Firewall"].Equal(at) {
		t.Fatal("recent window or journal counts lost")
	}
}

func BenchmarkJournalReplayWindow(b *testing.B) {
	at := time.Now().UTC()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		a := &App{lastSeen: map[string]time.Time{}}
		for i := 0; i < 5000; i++ {
			a.remember(Event{Time: at})
		}
	}
}

func TestStartupReplayPreservesJournalCounts(t *testing.T) {
	a := testApp(t)
	at := time.Now().UTC()
	f, err := os.Create(a.journalPath(at))
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for i := 0; i < 5000; i++ {
		if err = enc.Encode(Event{ID: fmt.Sprint(i), Time: at, Device: "Firewall", Message: "SSH log"}); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if restored.total != 5000 || len(restored.events) != 2000 || restored.events[0].ID != "3000" || restored.events[1999].ID != "4999" {
		t.Fatal("startup replay lost journal totals or latest events")
	}
}
