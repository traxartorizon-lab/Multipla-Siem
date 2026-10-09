package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func historyTimeRange(r *http.Request, now time.Time) (time.Time, time.Time, error) {
	end := now
	if value := r.URL.Query().Get("to"); value != "" {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return now, now, errors.New("data/hora final inválida")
		}
		end = parsed.UTC()
	}
	start := end.Add(-24 * time.Hour)
	if value := r.URL.Query().Get("from"); value != "" {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return now, now, errors.New("data/hora inicial inválida")
		}
		start = parsed.UTC()
	}
	if end.After(now) || !start.Before(end) || end.Sub(start) > 31*24*time.Hour {
		return now, now, errors.New("use um intervalo passado de até 31 dias, com início anterior ao fim")
	}
	return start, end, nil
}

// Read journals backwards so pagination never depends on the in-memory dashboard window.
func (a *App) historyEvents(r *http.Request, offset int, matchID string) ([]Event, bool, bool, error) {
	return a.readHistoryEvents(r, offset, matchID, false, 100)
}
func (a *App) readHistoryEvents(r *http.Request, offset int, matchID string, criticalOnly bool, limit int) ([]Event, bool, bool, error) {
	now := time.Now().UTC()
	cut, end, rangeErr := historyTimeRange(r, now)
	if rangeErr != nil {
		return nil, false, false, rangeErr
	}
	events := []Event{}
	matched := 0
	budget := int64(64 << 20)
	deadline := time.Now().Add(10 * time.Second)
	query := strings.ToLower(r.URL.Query().Get("q"))
	client := r.URL.Query().Get("client")
	if len(client) > 200 {
		return nil, false, false, errors.New("cliente inválido")
	}
	var classifier *App
	var clientIndex map[string]string
	if matchID == "" {
		a.mu.Lock()
		clientIndex = a.eventClientIndex()
		if criticalOnly {
			classifier = &App{state: State{CriticalPatterns: map[string]CriticalPattern{}, AlertReviews: map[string]AlertReview{}}}
			for k, v := range a.state.CriticalPatterns {
				classifier.state.CriticalPatterns[k] = v
			}
			for k, v := range a.state.AlertReviews {
				classifier.state.AlertReviews[k] = v
			}
		}
		a.mu.Unlock()
	}
	for day := end; !day.Before(cut.Truncate(24 * time.Hour)); day = day.AddDate(0, 0, -1) {
		path := a.journalPath(day)
		err := regularFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return events, false, false, err
		}
		f, err := os.Open(path)
		if err != nil {
			return events, false, false, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return events, false, false, err
		}
		position := st.Size()
		carry := []byte{}
		for position > 0 {
			if budget <= 0 || time.Now().After(deadline) || r.Context().Err() != nil {
				f.Close()
				return events, false, true, nil
			}
			size := int64(64 << 10)
			if size > position {
				size = position
			}
			if size > budget {
				size = budget
			}
			position -= size
			budget -= size
			chunk := make([]byte, size)
			_, err = f.ReadAt(chunk, position)
			if err != nil {
				f.Close()
				return events, false, false, err
			}
			chunk = append(chunk, carry...)
			lines := bytes.Split(chunk, []byte{'\n'})
			first := 0
			if position > 0 {
				carry = append([]byte{}, lines[0]...)
				first = 1
				if len(carry) > 262144 {
					f.Close()
					return events, false, true, nil
				}
			}
			for i := len(lines) - 1; i >= first; i-- {
				var event Event
				if json.Unmarshal(lines[i], &event) != nil || event.Time.Before(cut) || event.Time.After(end) {
					continue
				}
				if matchID != "" {
					if event.ID == matchID {
						f.Close()
						return []Event{event}, false, false, nil
					}
					continue
				}
				if query != "" && !strings.Contains(strings.ToLower(event.Message+" "+event.Device+" "+event.SourceIP+" "+event.SenderIP+" "+event.Rule), query) {
					continue
				}
				if client != "" {
					assigned := clientForEvent(clientIndex, event)
					if (client == "~unassigned" && assigned != "") || (client != "~unassigned" && assigned != client) {
						continue
					}
				}
				if criticalOnly {
					event = classifier.classifiedEvent(event)
					if (event.Level < 12 || (event.Review != nil && event.Review.Status == "false_positive")) && !(r.URL.Path == "/api/events/critical-ips" && securityLogSourceIP(event.Message) != "") {
						continue
					}
				}
				matched++
				if matched <= offset {
					continue
				}
				if len(events) == limit {
					f.Close()
					return events, true, false, nil
				}
				events = append(events, event)
			}
		}
		f.Close()
	}
	return events, false, false, nil
}
func (a *App) registerHistoryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/events/history", a.auth(func(w http.ResponseWriter, r *http.Request) {
		offset := 0
		if text := r.URL.Query().Get("offset"); text != "" {
			v, err := strconv.Atoi(text)
			if err != nil || v < 0 || v > 100000 {
				http.Error(w, "Página inválida", 400)
				return
			}
			offset = v
		}
		if len(r.URL.Query().Get("q")) > 200 || len(r.URL.Query().Get("client")) > 200 {
			http.Error(w, "Busca muito longa", 400)
			return
		}
		if _, _, err := historyTimeRange(r, time.Now().UTC()); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		select {
		case reportSlots <- struct{}{}:
			defer func() { <-reportSlots }()
		default:
			http.Error(w, "Consulta em andamento; tente novamente", 429)
			return
		}
		events, more, partial, err := a.historyEvents(r, offset, "")
		if err != nil {
			http.Error(w, "Falha ao ler histórico", 500)
			return
		}
		a.mu.Lock()
		for i := range events {
			e := &events[i]
			if review, ok := a.state.AlertReviews[e.ID]; ok {
				copy := review
				e.Review = &copy
				if copy.Level >= 12 && copy.Status != "false_positive" {
					marked := *e
					marked.Level = copy.Level
					e.Diagnosis = localDiagnosis(marked)
				}
			}
			if e.Diagnosis == nil && (e.Classification == nil || e.Classification.Critical) {
				e.Diagnosis = localDiagnosis(*e)
			}
			if result, ok := a.state.ModelDiagnoses[diagnosisKey(*e)]; ok {
				copy := result
				e.ModelDiagnosis = &copy
			}
			*e = a.classifiedEvent(*e)
		}
		a.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"events": events, "more": more, "partial": partial, "offset": offset, "hours": 24})
	}))
}
