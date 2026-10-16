package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func repeatSeed(at time.Time) Event {
	return Event{ID: token(), Time: at, Tenant: "A", Device: "router", SenderIP: "100.64.0.10", Kind: "proxmox", Protocol: "syslog", SourceIP: "198.51.100.5", Message: "service failure code=5 dstport=22"}
}
func TestRepetitionDailyBoundaryRestartAndRing(t *testing.T) {
	a := testApp(t)
	now := time.Now().UTC()
	seed := repeatSeed(now)
	key := problemKey(seed)
	for i := 1; i <= 19; i++ {
		e := seed
		e.ID = fmt.Sprint(i)
		e = a.trackProblemLocked(e)
		if e.ProblemKey != "" {
			t.Fatal("early suppression", i)
		}
		if !a.appendEvent(e) {
			t.Fatal("append failed")
		}
	}
	e := seed
	e.ID = "20"
	e = a.trackProblemLocked(e)
	if e.ProblemKey != key || !a.appendEvent(e) {
		t.Fatal("20th not grouped")
	}
	if len(a.events) != 19 {
		t.Fatal("20th leaked live", len(a.events))
	}
	st, _ := os.Stat(a.journalPath(now))
	before := st.Size()
	for i := 21; i <= 45; i++ {
		e := seed
		e.ID = fmt.Sprint(i)
		e = a.trackProblemLocked(e)
		if !a.appendEvent(e) {
			t.Fatal("ring append failed")
		}
	}
	if a.total != 45 {
		t.Fatal("suppressed receipts missing from total", a.total)
	}
	st, _ = os.Stat(a.journalPath(now))
	if st.Size() != before {
		t.Fatal("global journal grew")
	}
	w := a.repeatWindows[key]
	if w.Group.Count != 45 || w.Group.Suppressed != 26 || len(w.Events) != 20 || w.Events[0].ID != "26" || w.Events[19].ID != "45" {
		t.Fatalf("wrong ring: %+v", w.Group)
	}
	if !a.eventHiddenLocked(seed) {
		t.Fatal("group remains globally visible")
	}
	restart, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if restart.total != 45 {
		t.Fatal("received total lost on restart", restart.total)
	}
	w = restart.repeatWindows[key]
	if w.Group.Count != 45 || len(w.Events) != 20 || w.Events[0].ID != "26" {
		t.Fatal("restart lost ring")
	}
	next := seed
	next.Time = now.AddDate(0, 0, 1)
	next.ID = "newday"
	next = restart.trackProblemLocked(next)
	if next.ProblemKey != "" || restart.repeatWindows[key].Group.Count != 1 || len(restart.repeatWindows[key].Events) != 1 {
		t.Fatal("day did not reset")
	}
	// Staged next-slot write without metadata commit must not replace committed data.
	window := restart.repeatWindows[key]
	stage := repeatSlot{window.Sequence + 1, window.Group.Day, Event{ID: "uncommitted"}}
	if err := atomicJSON(restart.repeatSlotPath(key, stage.Count), stage); err != nil {
		t.Fatal(err)
	}
	again, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if again.repeatWindows[key].Events[0].ID != "newday" {
		t.Fatal("uncommitted slot exposed")
	}
	files, _ := os.ReadDir(filepath.Dir(a.repeatPath(key)))
	if len(files) > 22 {
		t.Fatal("unbounded slot files", len(files))
	}
}
func TestRepetitionIdentityPreservesSecurityFields(t *testing.T) {
	e := repeatSeed(time.Now())
	e.Message = "<30>Oct 14 12:01:02 host sshd[123]: denied from 198.51.100.5 port 22 code 5"
	key := problemKey(e)
	same := e
	same.Message = "<30>Oct 14 13:05:09 host sshd[987]: denied from 198.51.100.5 port 22 code 5"
	if problemKey(same) != key {
		t.Fatal("transport timestamp/PID not normalized")
	}
	variants := []Event{e, e, e, e, e, e, e, e}
	variants[0].Tenant = "B"
	variants[1].SenderIP = "100.64.0.11"
	variants[2].Device = "other"
	variants[3].SourceIP = "198.51.100.6"
	variants[4].Level = 12
	variants[5].Protocol = "webhook"
	variants[6].Message = strings.Replace(e.Message, "port 22", "port 23", 1)
	variants[7].Message = strings.Replace(e.Message, "code 5", "code 6", 1)
	for i, v := range variants {
		if problemKey(v) == key {
			t.Fatal("semantic distinction collapsed", i)
		}
	}
}
func TestRepetitionStorageFailureAndTenantQuota(t *testing.T) {
	a := testApp(t)
	e := repeatSeed(time.Now().UTC())
	key := problemKey(e)
	for i := 0; i < 19; i++ {
		a.trackProblemLocked(e)
	}
	// A directory at the metadata path makes its atomic commit fail on all platforms.
	if err := os.Remove(a.repeatPath(key)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(a.repeatPath(key), 0700); err != nil {
		t.Fatal(err)
	}
	e = a.trackProblemLocked(e)
	if e.ProblemKey != "" || a.repeatWindows[key].Group.Count != 19 {
		t.Fatal("failed persistence silently suppressed receipt")
	}
	if !a.appendEvent(e) {
		t.Fatal("global fallback unavailable")
	}
	b := testApp(t)
	for i := 0; i < repeatTenantLimit; i++ {
		v := repeatSeed(time.Now().UTC())
		v.Message = fmt.Sprint(i)
		b.trackProblemLocked(v)
	}
	v := repeatSeed(time.Now().UTC())
	v.Message = "over tenant quota"
	b.trackProblemLocked(v)
	if len(b.repeatWindows) != repeatTenantLimit {
		t.Fatal("tenant quota exceeded")
	}
	v.Tenant = "B"
	b.trackProblemLocked(v)
	if len(b.repeatWindows) != repeatTenantLimit+1 {
		t.Fatal("one tenant exhausted others")
	}
}
func TestRepetitionOriginalAlertsAndDerivedEffects(t *testing.T) {
	a := testApp(t)
	e := repeatSeed(time.Now().UTC())
	e.Alert = true
	e.Level = 12
	e.Rule = "original webhook"
	e.Kind = "webhook"
	for i := 0; i < 21; i++ {
		e.ID = token()
		v := a.trackProblemLocked(e)
		if !a.appendEvent(v) {
			t.Fatal("storage failed")
		}
	}
	w := a.repeatWindows[problemKey(e)]
	if w.Group.Count != 21 || len(w.Events) != 20 {
		t.Fatal("original alerts not counted")
	}
	derived := e
	derived.ParentID = e.ID
	derived.ProblemKey = problemKey(e)
	derived.ID = token()
	a.trackProblemLocked(derived)
	a.appendEvent(derived)
	if a.repeatWindows[problemKey(e)].Group.Count != 21 {
		t.Fatal("derived counted twice")
	}
	found := false
	for _, n := range a.state.Notifications {
		if n.EventID == derived.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("derived notification lost")
	}
}
func TestRepetitionGroupReadExportAndTenantBoundary(t *testing.T) {
	a := testApp(t)
	e := repeatSeed(time.Now().UTC())
	for i := 0; i < 24; i++ {
		e.ID = token()
		a.trackProblemLocked(e)
	}
	key := problemKey(e)
	h := a.routes()
	req := featureRequest(a, "admin@gmail.com", "GET", "/api/problem-devices/events?group="+key, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var data struct {
		Events []Event `json:"events"`
	}
	json.Unmarshal(w.Body.Bytes(), &data)
	if len(data.Events) != 20 {
		t.Fatal("read not bounded")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/problem-devices/events?group="+key+"&export=1", nil))
	if w.Code != 200 || strings.Count(strings.TrimSpace(w.Body.String()), "\n") != 19 {
		t.Fatal("ring export failed", w.Code)
	}
	// Unauthenticated queries cannot enumerate or export windows.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/problem-devices/events?group="+key, nil))
	if w.Code == 200 {
		t.Fatal("unauthorized group read")
	}
}
func TestDashboardManualCoordinatesValidationAndPreference(t *testing.T) {
	a := testApp(t)
	body := []byte(`{"order":["collection"],"snap":false,"cards":{"collection":{"x":113,"y":257,"pixel_width":351,"height":241}}}`)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "PUT", "/api/dashboard/layout", body))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	p := a.state.Preferences["admin@gmail.com"]
	if p.DashboardSnap == nil || *p.DashboardSnap || *p.DashboardCards["collection"].X != 113 {
		t.Fatal("manual preference not persisted")
	}
	for _, bad := range []string{`{"x":-1}`, `{"y":48001}`, `{"pixel_width":119}`, `{"pixel_width":8001}`} {
		var c DashboardCardSettings
		json.Unmarshal([]byte(bad), &c)
		if validateDashboardSettings(map[string]DashboardCardSettings{"collection": c}) == nil {
			t.Fatal("bad coordinate allowed", bad)
		}
	}
}
func TestRepetitionBurstIO(t *testing.T) {
	a := testApp(t)
	e := repeatSeed(time.Now().UTC())
	e.Message = strings.Repeat("x", 16<<10)
	start := time.Now()
	const receipts = 200
	for i := 0; i < receipts; i++ {
		e.ID = token()
		v := a.trackProblemLocked(e)
		if i >= 19 && v.ProblemKey == "" {
			t.Fatal("burst fallback", i)
		}
	}
	files, _ := os.ReadDir(filepath.Dir(a.repeatPath(problemKey(e))))
	var bytes int64
	for _, f := range files {
		st, _ := f.Info()
		bytes += st.Size()
	}
	if bytes > 600<<10 || len(files) > 22 {
		t.Fatal("retention grew with burst", bytes, len(files))
	}
	t.Logf("200 receipts x16KiB: %v elapsed, %d bytes retained, %d files; 1 new slot + metadata per receipt (not 20 payload rewrites)", time.Since(start), bytes, len(files))
}

func TestManualProblemSeedWithAutomaticOff(t *testing.T) {
	a := testApp(t)
	off := false
	a.state.ProblemAutomatic = &off
	e := repeatSeed(time.Now().UTC())
	if !a.appendEvent(e) {
		t.Fatal("seed")
	}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/events/"+e.ID+"/hide", []byte(`{"days":3}`)))
	if w.Code != 200 {
		t.Fatal("manual hide", w.Code, w.Body.String())
	}
	key := problemKey(e)
	for _, app := range []*App{a, func() *App {
		restart, err := newApp(a.cfg, a.configPath, false)
		if err != nil {
			t.Fatal(err)
		}
		return restart
	}()} {
		for _, suffix := range []string{"", "&export=1"} {
			w := httptest.NewRecorder()
			app.routes().ServeHTTP(w, featureRequest(app, "admin@gmail.com", "GET", "/api/problem-devices/events?group="+key+suffix, nil))
			if w.Code != 200 || !strings.Contains(w.Body.String(), e.ID) {
				t.Fatal("manual seed missing", w.Code, w.Body.String())
			}
		}
		if app.repeatWindows[key].Group.Count != 1 || app.repeatWindows[key].Group.Suppressed != 0 {
			t.Fatal("seed counted twice")
		}
	}
}
