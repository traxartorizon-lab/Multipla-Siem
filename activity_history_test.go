package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestActivityHistoryCountsOriginalLogsAndAggregation(t *testing.T) {
	a := testApp(t)
	now := time.Now().UTC().Add(-8 * time.Minute)
	file, err := os.OpenFile(a.journalPath(now), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := json.NewEncoder(file).Encode(Event{Time: now, Device: "PC", Alert: i == 2}); err != nil {
			t.Fatal(err)
		}
	}
	file.Close()
	for _, mode := range []string{"average", "maximum"} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/dashboard/activity?period=6h&mode="+mode, nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var data struct {
			Series []activityHistoryGroup `json:"series"`
			Step   int                    `json:"interval_minutes"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, s := range data.Series {
			if s.Name != "PC" {
				continue
			}
			found = true
			if s.Total != 2 {
				t.Fatal("derived alert counted", s.Total)
			}
			for _, v := range s.Bins {
				if v > 0 {
					want := 2.
					if mode == "average" {
						want = 2. / float64(data.Step)
					}
					if v != want {
						t.Fatal(mode, v, want)
					}
				}
			}
		}
		if !found {
			t.Fatal("missing PC")
		}
	}
	for _, query := range []string{"period=year&mode=average", "period=30m&mode=invalid"} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/dashboard/activity?"+query, nil))
		if w.Code != 400 {
			t.Fatal("invalid query", w.Code)
		}
	}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, httptest.NewRequest("GET", "/api/dashboard/activity?period=1h&mode=average", nil))
	if w.Code == 200 {
		t.Fatal("unauthenticated")
	}
}
