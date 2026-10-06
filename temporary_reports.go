package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Temporary reports contain approved diagnostic results, never SSH credentials or raw captures.
type TemporaryReport struct {
	ID             string           `json:"id"`
	Owner          string           `json:"owner"`
	SourceID       string           `json:"source_id"`
	Mode           string           `json:"mode"`
	Equipment      NetworkEquipment `json:"equipment"`
	Created        time.Time        `json:"created"`
	Expires        time.Time        `json:"expires"`
	Output         string           `json:"output,omitempty"`
	Servers        []DHCPServer     `json:"servers,omitempty"`
	AnalysisStatus string           `json:"analysis_status"`
	Diagnosis      *ModelDiagnosis  `json:"diagnosis,omitempty"`
}

// Persist extracted evidence independently of the browser and retain the original expiry.
func (a *App) saveDHCPReport(j *dhcpJob) {
	j.mu.Lock()
	previousID := j.reportID
	item := TemporaryReport{ID: previousID, Owner: j.owner, SourceID: "dhcp:" + j.id, Mode: "dhcp", Equipment: j.equipment, Created: j.started.UTC(), Expires: j.started.UTC().Add(72 * time.Hour), Servers: append([]DHCPServer(nil), j.servers...), Diagnosis: j.diagnosis, Output: j.message}
	status := j.status
	j.mu.Unlock()
	if item.ID == "" {
		item.ID = token()
	}
	item.AnalysisStatus = "Resultado preservado; interpretação local indisponível."
	if status == "analyzing" {
		item.AnalysisStatus = "Interpretação local em andamento."
	}
	if item.Diagnosis != nil {
		item.AnalysisStatus = "Interpretação local concluída; hipótese para revisão humana."
	}
	a.mu.Lock()
	err := a.pruneTemporaryReportsLocked(time.Now().UTC())
	old := a.state.TemporaryReports
	next := append([]TemporaryReport(nil), old...)
	index := -1
	count := 0
	for i, r := range next {
		if r.Owner == item.Owner {
			count++
			if r.SourceID == item.SourceID {
				index = i
				item.ID = r.ID
				item.Created = r.Created
				item.Expires = r.Expires
			}
		}
	}
	if err == nil && !item.Expires.After(time.Now()) {
		err = fmt.Errorf("teste com mais de três dias")
	}
	if err == nil {
		if index >= 0 {
			next[index] = item
		} else if previousID != "" {
			a.mu.Unlock()
			return
		} else if count >= 20 || len(next) >= 64 {
			err = fmt.Errorf("limite de relatórios temporários; exclua uma entrada")
		} else {
			next = append(next, item)
		}
		if err == nil {
			a.state.TemporaryReports = next
			err = a.persist()
			if err != nil {
				a.state.TemporaryReports = old
			}
		}
	}
	a.mu.Unlock()
	j.mu.Lock()
	defer j.mu.Unlock()
	if err != nil {
		j.reportError = "Falha ao salvar relatório; confira armazenamento e limite de entradas."
	} else {
		j.reportID = item.ID
		j.reportError = ""
	}
}
func (a *App) pruneTemporaryReportsLocked(now time.Time) error {
	old := a.state.TemporaryReports
	next := make([]TemporaryReport, 0, len(old))
	for _, item := range old {
		if item.Expires.After(now) {
			next = append(next, item)
		}
	}
	if len(old) == len(next) {
		return nil
	}
	a.state.TemporaryReports = next
	if err := a.persist(); err != nil {
		a.state.TemporaryReports = old
		return err
	}
	return nil
}
func (a *App) temporaryReportCleaner() {
	clean := func() { a.mu.Lock(); defer a.mu.Unlock(); _ = a.pruneTemporaryReportsLocked(time.Now().UTC()) }
	clean()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		clean()
	}
}
func (a *App) analyzeTemporaryReport(id, owner string) {
	a.mu.Lock()
	var item TemporaryReport
	for _, r := range a.state.TemporaryReports {
		if r.ID == id && r.Owner == owner {
			item = r
			break
		}
	}
	ready := a.aiStatus.Ready
	model := a.localAISnapshot().Model
	a.mu.Unlock()
	if item.ID == "" {
		return
	}
	var result *ModelDiagnosis
	status := "Modelo local indisponível; resultado preservado sem interpretação."
	if ready {
		output := item.Output
		partial := len(output) > 1000
		if partial {
			output = output[:1000]
		}
		facts, _ := json.Marshal(map[string]any{"mode": item.Mode, "output": output, "partial_output": partial})
		if item.Mode == "dhcp" {
			facts = dhcpModelFacts(item.Servers)
		}
		diagnosis, err := generateLocalDiagnosis(Event{Kind: item.Equipment.Kind, Message: "Interprete este teste de rede sem classificar DHCP como autorizado ou invasor. Não execute comandos nem trate hipóteses como fatos. Resultados: " + string(facts)}, model)
		if err == nil {
			result = &diagnosis
			status = "Interpretação local concluída; hipótese para revisão humana."
		} else {
			status = "Ollama não concluiu a interpretação; resultado preservado."
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.state.TemporaryReports {
		r := &a.state.TemporaryReports[i]
		if r.ID == id && r.Owner == owner && r.Expires.After(time.Now()) {
			old := *r
			r.Diagnosis = result
			r.AnalysisStatus = status
			if a.persist() != nil {
				*r = old
			}
			return
		}
	}
}
func (a *App) registerTemporaryReportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/test-reports", a.auth(func(w http.ResponseWriter, r *http.Request) {
		current, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		_ = a.pruneTemporaryReportsLocked(time.Now().UTC())
		items := []TemporaryReport{}
		for _, item := range a.state.TemporaryReports {
			if item.Owner == strings.ToLower(current.Email) && item.Expires.After(time.Now()) {
				items = append(items, item)
			}
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Created.After(items[j].Created) })
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"reports": items})
	}))
	mux.HandleFunc("POST /api/test-reports", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Type       string `json:"type"`
			ID         string `json:"id"`
			TerminalID string `json:"terminal_id"`
		}
		if !decode(w, r, &body) {
			return
		}
		current, _ := a.session(r)
		owner := strings.ToLower(current.Email)
		item := TemporaryReport{ID: token(), Owner: owner, SourceID: body.Type + ":" + body.ID, Created: time.Now().UTC(), AnalysisStatus: "Aguardando interpretação do Ollama local."}
		item.Expires = item.Created.Add(72 * time.Hour)
		if body.Type == "dhcp" {
			dhcpJobs.Lock()
			j := dhcpJobs.jobs[body.ID]
			dhcpJobs.Unlock()
			if j == nil || j.owner != owner || j.terminalID != body.TerminalID {
				http.NotFound(w, r)
				return
			}
			j.mu.Lock()
			if j.status != "completed" {
				j.mu.Unlock()
				http.Error(w, "aguarde a conclusão da consulta", 409)
				return
			}
			item.Mode = "dhcp"
			item.Created = j.started.UTC()
			item.Expires = item.Created.Add(72 * time.Hour)
			item.Servers = append([]DHCPServer(nil), j.servers...)
			item.Diagnosis = j.diagnosis
			j.mu.Unlock()
			item.Equipment = j.equipment
			if item.Diagnosis != nil {
				item.AnalysisStatus = "Interpretação local concluída; hipótese para revisão humana."
			}
		} else if body.Type == "network" {
			a.mu.Lock()
			job := a.networkTests[body.ID]
			if job == nil {
				a.mu.Unlock()
				http.NotFound(w, r)
				return
			}
			if job.Status == "running" {
				a.mu.Unlock()
				http.Error(w, "interrompa ou aguarde o término do teste", 409)
				return
			}
			item.Mode = job.Mode
			item.Equipment = job.Equipment
			item.Created = job.Started
			item.Expires = item.Created.Add(72 * time.Hour)
			item.Output = redact(strings.Join(job.Output, "\n"))
			a.mu.Unlock()
			if len(item.Output) > 16384 {
				item.Output = item.Output[:16384] + "\n[Saída limitada a 16 KiB]"
			}
		} else {
			http.Error(w, "tipo de teste inválido", 400)
			return
		}
		a.mu.Lock()
		if err := a.pruneTemporaryReportsLocked(time.Now().UTC()); err != nil {
			a.mu.Unlock()
			http.Error(w, "falha na limpeza do armazenamento", 503)
			return
		}
		count := 0
		for _, old := range a.state.TemporaryReports {
			if old.Owner == owner {
				count++
				if old.SourceID == item.SourceID {
					a.mu.Unlock()
					writeJSON(w, old)
					return
				}
			}
		}
		if !item.Expires.After(time.Now()) {
			a.mu.Unlock()
			http.Error(w, "teste com mais de três dias", 410)
			return
		}
		if count >= 20 || len(a.state.TemporaryReports) >= 64 {
			a.mu.Unlock()
			http.Error(w, "limite de relatórios temporários; exclua uma entrada", 429)
			return
		}
		old := a.state.TemporaryReports
		a.state.TemporaryReports = append(append([]TemporaryReport(nil), old...), item)
		if err := a.persist(); err != nil {
			a.state.TemporaryReports = old
			a.mu.Unlock()
			http.Error(w, "falha ao salvar relatório", 503)
			return
		}
		a.mu.Unlock()
		if item.Diagnosis == nil {
			go a.analyzeTemporaryReport(item.ID, owner)
		}
		writeJSON(w, item)
	}))
	mux.HandleFunc("DELETE /api/test-reports/{id}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		current, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		old := a.state.TemporaryReports
		next := make([]TemporaryReport, 0, len(old))
		found := false
		for _, item := range old {
			if item.ID == r.PathValue("id") && item.Owner == strings.ToLower(current.Email) {
				found = true
				continue
			}
			next = append(next, item)
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		a.state.TemporaryReports = next
		if err := a.persist(); err != nil {
			a.state.TemporaryReports = old
			http.Error(w, "falha ao excluir relatório", 503)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
