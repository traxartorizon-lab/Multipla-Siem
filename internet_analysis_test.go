package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestResearchQueryContainsOnlyConstantTerms(t *testing.T) {
	q := researchQuery(Event{Kind: "pfsense", Message: "192.168.1.2 client-secret password=123 kernel panic"})
	if q != "pfSense kernel panic troubleshooting documentation" {
		t.Fatal(q)
	}
	if strings.Contains(q, "192.168") {
		t.Fatal(q)
	}
	if researchQuery(Event{Message: "private unknown error account xyz"}) != "" {
		t.Fatal("unknown log escaped")
	}
}

func TestResearchRequestDoesNotTransmitLogSecrets(t *testing.T) {
	old := researchHTTP
	values := credentialValues
	defer func() { researchHTTP = old; credentialValues = values }()
	credentialValues = map[string]string{"BRAVE_SEARCH_API_KEY": "provider-key"}
	researchHTTP = &http.Client{Transport: aiRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.search.brave.com" || r.URL.Query().Get("q") != "Proxmox out of memory troubleshooting documentation" {
			t.Fatalf("unexpected query %s", r.URL)
		}
		if r.Body != nil {
			t.Fatal("log body transmitted")
		}
		for _, private := range []string{"192.168.1.20", "alice", "PRIVATE_TOKEN", "PRIVATE_PASSWORD", "clientname"} {
			if strings.Contains(r.URL.String(), private) {
				t.Fatal("private data transmitted")
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"web":{"results":[{"title":"Reference","url":"https://docs.example.org/error","description":"Memory troubleshooting"},{"title":"Invalid","url":"javascript:alert(1)"}]}}`))}, nil
	})}
	sources, _ := internetResearch(Event{Kind: "proxmox", Message: "clientname alice 192.168.1.20 token=PRIVATE_TOKEN password=PRIVATE_PASSWORD out of memory"})
	if len(sources) != 1 {
		t.Fatal(sources)
	}
}
