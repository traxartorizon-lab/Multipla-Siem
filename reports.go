package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var reportSlots = make(chan struct{}, 2)

type reportFilter struct {
	cutoff   time.Time
	Start    string `json:"start"`
	End      string `json:"end"`
	Device   string `json:"device"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Type     string `json:"type"`
	SourceIP string `json:"source_ip"`
}
type eventReport struct {
	CriticalBySourceIP map[string]int `json:"critical_by_source_ip"`
	CriticalWithoutIP  int            `json:"critical_without_ip"`
	Filter             reportFilter   `json:"filter"`
	Generated          time.Time      `json:"generated"`
	Matched            int            `json:"matched"`
	Originals          int            `json:"originals"`
	Alerts             int            `json:"alerts"`
	Critical           int            `json:"critical"`
	Scanned            int            `json:"scanned"`
	Invalid            int            `json:"invalid"`
	Partial            bool           `json:"partial"`
	Missing            []string       `json:"missing_days"`
	ByDevice           map[string]int `json:"by_device"`
	BySeverity         map[string]int `json:"by_severity"`
	Events             []Event        `json:"events"`
}

func eventSeverity(e Event) string {
	if criticalEvent(e) {
		return "critical"
	}
	if e.Level >= 10 {
		return "high"
	}
	if e.Level >= 7 {
		return "medium"
	}
	if e.Level > 0 {
		return "low"
	}
	return "log"
}
func (f reportFilter) matches(e Event) bool {
	return (f.Device == "" || e.Device == f.Device) && (f.Kind == "" || e.Kind == f.Kind || f.Kind == "infrastructure" && (e.Kind == "pfsense" || e.Kind == "proxmox")) && (f.SourceIP == "" || securitySourceIP(e) == f.SourceIP) && (f.Severity == "" || eventSeverity(e) == f.Severity) && (f.Type == "" || f.Type == "alerts" && e.Alert || f.Type == "logs" && !e.Alert)
}
func parseReportFilter(r *http.Request) (reportFilter, time.Time, time.Time, error) {
	q := r.URL.Query()
	f := reportFilter{Start: q.Get("start"), End: q.Get("end"), Device: q.Get("device"), Kind: q.Get("kind"), Severity: q.Get("severity"), Type: q.Get("type"), SourceIP: q.Get("source_ip")}
	if f.SourceIP != "" {
		ip, err := netip.ParseAddr(f.SourceIP)
		if err != nil {
			return f, time.Time{}, time.Time{}, errors.New("IP de origem inválido")
		}
		f.SourceIP = ip.Unmap().String()
	}
	start, e1 := time.Parse("2006-01-02", f.Start)
	end, e2 := time.Parse("2006-01-02", f.End)
	if e1 != nil || e2 != nil || end.Before(start) || end.Sub(start) > 30*24*time.Hour || end.After(time.Now().UTC()) || len(f.Device) > 200 || len(f.Kind) > 80 {
		return f, start, end, errors.New("período inválido: use até 31 dias UTC e filtros dentro dos limites")
	}
	if f.Severity != "" && f.Severity != "critical" && f.Severity != "high" && f.Severity != "medium" && f.Severity != "low" && f.Severity != "log" {
		return f, start, end, errors.New("nível inválido")
	}
	if f.Type != "" && f.Type != "alerts" && f.Type != "logs" {
		return f, start, end, errors.New("tipo inválido")
	}
	return f, start, end, nil
}
func (a *App) buildReport(r *http.Request, filter reportFilter, start, end time.Time) (eventReport, error) {
	result := eventReport{Filter: filter, Generated: time.Now().UTC(), CriticalBySourceIP: map[string]int{}, ByDevice: map[string]int{}, BySeverity: map[string]int{}, Events: []Event{}, Missing: []string{}}
	remaining := int64(64 << 20)
	deadline := time.Now().Add(20 * time.Second)
	for day := start; !day.After(end); day = day.AddDate(0, 0, 1) {
		path := a.journalPath(day)
		fileErr := regularFile(path)
		if os.IsNotExist(fileErr) {
			result.Missing = append(result.Missing, day.Format("2006-01-02"))
			continue
		}
		if fileErr != nil {
			return result, fileErr
		}
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			result.Missing = append(result.Missing, day.Format("2006-01-02"))
			continue
		}
		if err != nil {
			return result, err
		}
		reader := &io.LimitedReader{R: file, N: remaining + 1}
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 65536), 256<<10)
		for scanner.Scan() {
			if r.Context().Err() != nil {
				file.Close()
				return result, r.Context().Err()
			}
			if time.Now().After(deadline) || reader.N <= 1 {
				result.Partial = true
				break
			}
			var event Event
			if json.Unmarshal(scanner.Bytes(), &event) != nil {
				result.Invalid++
				continue
			}
			if event.Time.Before(start) || !event.Time.Before(end.AddDate(0, 0, 1)) {
				continue
			}
			if !filter.cutoff.IsZero() && (event.Time.Before(filter.cutoff) || event.Time.After(time.Now())) {
				continue
			}
			result.Scanned++
			if !filter.matches(event) {
				continue
			}
			result.Matched++
			if event.Alert {
				result.Alerts++
			} else {
				result.Originals++
			}
			severity := eventSeverity(event)
			result.BySeverity[severity]++
			if severity == "critical" {
				result.Critical++
				origin := securitySourceIP(event)
				if origin == "" {
					result.CriticalWithoutIP++
				} else {
					if _, ok := result.CriticalBySourceIP[origin]; !ok && len(result.CriticalBySourceIP) >= 500 {
						origin = "Outros IPs"
					}
					result.CriticalBySourceIP[origin]++
				}
			}
			// Bound aggregation even if historical inputs contain unexpected device names.
			device := event.Device
			if _, ok := result.ByDevice[device]; !ok && len(result.ByDevice) >= 500 {
				device = "Outros dispositivos"
			}
			result.ByDevice[device]++
			if len(result.Events) < 1000 {
				event.SourceIP = securitySourceIP(event)
				event.Message = redact(event.Message)
				result.Events = append(result.Events, event)
			}
		}
		remaining -= remaining + 1 - reader.N
		scanErr := scanner.Err()
		file.Close()
		if scanErr != nil {
			return result, scanErr
		}
		if result.Partial || remaining <= 0 {
			result.Partial = true
			break
		}
	}
	return result, nil
}

func csvSafe(s string) string {
	// Prevent spreadsheet formulas in untrusted device names and messages.
	t := strings.TrimLeft(s, " \t\r\n")
	if len(t) > 0 && strings.ContainsRune("=+-@", rune(t[0])) || strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\r") {
		return "'" + s
	}
	return s
}
func (a *App) registerReportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/reports", a.auth(func(w http.ResponseWriter, r *http.Request) {
		f, start, end, err := parseReportFilter(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		format := r.URL.Query().Get("format")
		if format != "" && format != "json" && format != "csv" {
			http.Error(w, "formato inválido", 400)
			return
		}
		select {
		case reportSlots <- struct{}{}:
			defer func() { <-reportSlots }()
		default:
			http.Error(w, "há relatórios em processamento; tente novamente", 429)
			return
		}
		result, err := a.buildReport(r, f, start, end)
		if err != nil {
			http.Error(w, "não foi possível ler o histórico do relatório", 500)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if format == "csv" {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="multipla-relatorio-registros.csv"`)
			writer := csv.NewWriter(w)
			writer.Write([]string{"Horário UTC", "Dispositivo", "Origem", "Tipo", "Nível", "Regra", "IP", "Mensagem"})
			for _, e := range result.Events {
				kind := "Log original"
				if e.Alert {
					kind = "Alerta"
				}
				writer.Write([]string{e.Time.UTC().Format(time.RFC3339), csvSafe(e.Device), csvSafe(e.Kind), kind, strconv.Itoa(e.Level), csvSafe(e.Rule), csvSafe(e.SourceIP), csvSafe(e.Message)})
			}
			writer.Flush()
			return
		}
		if format == "json" {
			w.Header().Set("Content-Disposition", `attachment; filename="multipla-relatorio.json"`)
		}
		writeJSON(w, result)
	}))
}

// The security report parser accepts pass/block and PID-prefixed pfSense logs.
// It never substitutes a device address for a missing event origin.
var reportFilterlog = regexp.MustCompile(`filterlog(?:\[[0-9]+\])?:\s*([^\r\n]+)`)

func securitySourceIP(e Event) string {
	normalize := func(text string) string {
		ip, err := netip.ParseAddr(strings.TrimSpace(text))
		if err != nil {
			return ""
		}
		return ip.Unmap().String()
	}
	if e.Kind == "pfsense" {
		if match := reportFilterlog.FindStringSubmatch(e.Message); len(match) > 1 {
			fields := strings.Split(match[1], ",")
			if len(fields) > 18 && fields[8] == "4" {
				return normalize(fields[18])
			}
			if len(fields) > 15 && fields[8] == "6" {
				return normalize(fields[15])
			}
			return ""
		}
	}
	if origin := sourceIP(e.Message, e.Kind); origin != "" {
		return normalize(origin)
	}
	return normalize(e.SourceIP)
}
