package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ResearchSource struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

var researchHTTP = &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}

func researchQuery(e Event) string {
	product := "Linux"
	switch e.Kind {
	case "pfsense":
		product = "pfSense"
	case "proxmox":
		product = "Proxmox"
	}
	// Only recognized constant error signatures leave the server; never raw log fields.
	m := strings.ToLower(e.Message)
	for _, term := range []string{"out of memory", "oom-kill", "kernel panic", "i/o error", "blk_update_request", "zpool", "zfs", "ecc", "temperature", "no space left on device", "authentication failure", "failed password", "dhcp", "watchdog", "segfault", "connection refused", "certificate expired", "checksum"} {
		if strings.Contains(m, term) {
			return product + " " + term + " troubleshooting documentation"
		}
	}
	return ""
}
func internetResearch(e Event) ([]ResearchSource, string) {
	key := secret("BRAVE_SEARCH_API_KEY")
	if key == "" {
		return nil, "Pesquisa não realizada: configure BRAVE_SEARCH_API_KEY."
	}
	q := researchQuery(e)
	if q == "" {
		return nil, "Pesquisa não realizada: erro sem assinatura técnica reconhecida; log não enviado."
	}
	req, _ := http.NewRequest("GET", "https://api.search.brave.com/res/v1/web/search?count=3&q="+url.QueryEscape(q), nil)
	req.Header.Set("X-Subscription-Token", key)
	req.Header.Set("Accept", "application/json")
	response, err := researchHTTP.Do(req)
	if err != nil {
		return nil, "Pesquisa indisponível; análise local mantida."
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, "Pesquisa indisponível; verifique a chave ou cota do provedor."
	}
	var data struct {
		Web struct {
			Results []ResearchSource `json:"results"`
		} `json:"web"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&data) != nil {
		return nil, "Resposta da pesquisa inválida."
	}
	result := []ResearchSource{}
	for _, source := range data.Web.Results {
		u, err := url.Parse(source.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || len(source.URL) > 700 {
			continue
		}
		source.Title = redact(source.Title)
		source.Description = redact(source.Description)
		if len(source.Title) > 150 {
			source.Title = source.Title[:150]
		}
		if len(source.Description) > 600 {
			source.Description = source.Description[:600]
		}
		result = append(result, source)
		if len(result) == 3 {
			break
		}
	}
	return result, "Pesquisa complementar: resumos do índice de busca; confirme nas fontes."
}
