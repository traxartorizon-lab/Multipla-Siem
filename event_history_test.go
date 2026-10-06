package main

import (
	"net/http/httptest"
	"net/url"
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

func TestHistoryFiltersStoredTimeRangeAndIP(t *testing.T) {
 a:=testApp(t);now:=time.Now().UTC()
 for _,e:=range []Event{
  {ID:"inside",Time:now.Add(-48*time.Hour),Message:"DHCP failure",SourceIP:"192.0.2.10"},
  {ID:"outside",Time:now.Add(-time.Hour),Message:"DHCP failure",SourceIP:"192.0.2.10"},
  {ID:"other",Time:now.Add(-48*time.Hour),Message:"DHCP failure",SourceIP:"192.0.2.11"},
 } {if !a.appendEvent(e){t.Fatal("journal")}}
 q:=url.Values{"from":{now.Add(-49*time.Hour).Format(time.RFC3339Nano)},"to":{now.Add(-47*time.Hour).Format(time.RFC3339Nano)},"q":{"192.0.2.10"}}
 events,more,partial,err:=a.historyEvents(httptest.NewRequest("GET","/api/events/history?"+q.Encode(),nil),0,"")
 if err!=nil || more || partial || len(events)!=1 || events[0].ID!="inside" {t.Fatal(events,more,partial,err)}
 for _,values:=range []url.Values{
  {"from":{"bad"}},
  {"from":{now.Format(time.RFC3339Nano)},"to":{now.Add(-time.Hour).Format(time.RFC3339Nano)}},
  {"from":{now.Add(-32*24*time.Hour).Format(time.RFC3339Nano)}},
 } {if _,_,err:=historyTimeRange(httptest.NewRequest("GET","/?"+values.Encode(),nil),now);err==nil {t.Fatal("invalid range accepted",values)}}
}
