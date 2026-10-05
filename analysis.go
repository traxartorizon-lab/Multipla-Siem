package main

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// Streaming models are bounded and manipulated only while App.mu is held.
// No executable instructions, network clients or firewall actions exist here.
const analysisDeviceLimit = 128
const analysisSourceLimit = 1024
const analysisWarmup = 20

var analysisFailure = regexp.MustCompile(`(?i)failed password|authentication failure|invalid user|authentication failed|login failed`)
var analysisSuccess = regexp.MustCompile(`(?i)accepted (?:password|publickey)|authentication successful|login successful`)
var analysisCritical = regexp.MustCompile(`(?i)kernel panic|out of memory: kill|oom-kill|invoked oom-killer|uncorrect(?:ed|able).*ecc|ecc.*uncorrect(?:ed|able)|critical temperature|temperature above threshold|smart.*(?:overall-health.*failed|prefailure|pre-fail.*failed)|(?:i/o error|buffer i/o error|blk_update_request.*error)|(?:zpool|zfs|pool).*\b(?:faulted|unavail)\b`)
var analysisError = regexp.MustCompile(`(?i)\berror\b|\bfailed\b|\bfatal\b|\bcritical\b`)

type analysisMinute struct {
	Minute   time.Time
	Counts   [3]int
	Mean     [3]float64
	Variance [3]float64
	Samples  int
	Last     [5]time.Time
	LastSeen time.Time
}
type analysisAttempts struct {
	Count       int
	First, Last time.Time
}
type localAnalyzer struct {
	Devices  map[string]*analysisMinute
	Attempts map[string]analysisAttempts
	Dropped  uint64
}
type analysisStatus struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`
	Devices       int    `json:"devices"`
	Ready         int    `json:"ready"`
	WarmupMinutes int    `json:"warmup_minutes"`
	DeviceLimit   int    `json:"device_limit"`
	SourceLimit   int    `json:"source_limit"`
	Skipped       uint64 `json:"skipped"`
}

func newLocalAnalyzer() *localAnalyzer {
	return &localAnalyzer{Devices: map[string]*analysisMinute{}, Attempts: map[string]analysisAttempts{}}
}
func (m *analysisMinute) advance(now time.Time) {
	minute := now.UTC().Truncate(time.Minute)
	if m.Minute.IsZero() {
		m.Minute = minute
		return
	}
	if !minute.After(m.Minute) {
		return
	}
	elapsed := int(minute.Sub(m.Minute) / time.Minute)
	if elapsed > 120 {
		*m = analysisMinute{Minute: minute, LastSeen: m.LastSeen}
		return
	}
	for j := 0; j < elapsed; j++ {
		for i := range m.Mean {
			x := float64(m.Counts[i])
			if j > 0 {
				x = 0
			}
			// Clip learned spikes after warmup to reduce baseline poisoning.
			if m.Samples >= analysisWarmup {
				x = math.Min(x, math.Max(4, m.Mean[i]+3*math.Sqrt(m.Variance[i]+1)))
			}
			if m.Samples == 0 {
				m.Mean[i] = x
			} else {
				d := x - m.Mean[i]
				m.Mean[i] += .1 * d
				m.Variance[i] = .9 * (m.Variance[i] + .1*d*d)
			}
		}
		if m.Samples < 100000 {
			m.Samples++
		}
	}
	m.Counts = [3]int{}
	m.Minute = minute
}
func category(e Event) int {
	if analysisFailure.MatchString(e.Message) {
		return 0
	}
	// pfSense filterlog parser populates SourceIP for action=block.
	if e.Kind == "pfsense" && e.SourceIP != "" && strings.Contains(e.Message, "filterlog") {
		return 1
	}
	if analysisError.MatchString(e.Message) {
		return 2
	}
	return -1
}
func analysisAlert(e Event, name, reason, detector string, level int) Event {
	e.ID = token()
	e.Alert = true
	e.Rule = name
	e.Level = level
	e.Detector = detector
	e.Message = reason + " | Evidência: " + e.Message
	return sanitizeEvent(e)
}
func (l *localAnalyzer) observe(e Event) []Event {
	if e.Alert {
		return nil
	}
	var alerts []Event
	if criticalEvent(e) {
		alert := analysisAlert(e, "Evento crítico analisado localmente", "Indicador crítico detectado; consulte o diagnóstico local.", "local-critical", 12)
		alert.ParentID = e.ID
		alerts = append(alerts, alert)
	}
	m := l.Devices[e.Device]
	if m == nil {
		if len(l.Devices) >= analysisDeviceLimit {
			l.Dropped++
			return alerts
		}
		m = &analysisMinute{}
		l.Devices[e.Device] = m
	}
	m.advance(e.Time)
	m.LastSeen = e.Time
	emit := func(slot int, name, reason, detector string, level int) {
		if !m.Last[slot].IsZero() && e.Time.Sub(m.Last[slot]) < 10*time.Minute {
			return
		}
		m.Last[slot] = e.Time
		alerts = append(alerts, analysisAlert(e, name, reason, detector, level))
	}
	key := e.Device + "|" + e.SourceIP
	if e.SourceIP != "" {
		b := l.Attempts[key]
		if !b.First.IsZero() && e.Time.Sub(b.First) > 5*time.Minute {
			delete(l.Attempts, key)
			b = analysisAttempts{}
		}
		if analysisFailure.MatchString(e.Message) {
			if b.Count == 0 {
				b.First = e.Time
			}
			if b.Count < 10000 {
				b.Count++
			}
			b.Last = e.Time
			if _, ok := l.Attempts[key]; ok || len(l.Attempts) < analysisSourceLimit {
				l.Attempts[key] = b
			} else {
				l.Dropped++
			}
		} else if analysisSuccess.MatchString(e.Message) && b.Count >= 5 {
			emit(4, "Acesso bem-sucedido após falhas repetidas", fmt.Sprintf("Foram observadas %d falhas em até cinco minutos antes de um acesso bem-sucedido do mesmo IP no mesmo dispositivo. Isso é suspeito, mas não comprova invasão.", b.Count), "local-correlation", 11)
			delete(l.Attempts, key)
		}
	}
	c := category(e)
	if c >= 0 {
		if m.Counts[c] < 1000000 {
			m.Counts[c]++
		}
		threshold := math.Max(8, m.Mean[c]+4*math.Sqrt(m.Variance[c]+1))
		if m.Samples >= analysisWarmup && float64(m.Counts[c]) > threshold {
			names := [3]string{"falhas de autenticação", "bloqueios do firewall", "erros de sistema"}
			emit(c, "Anomalia local: "+names[c], fmt.Sprintf("%d ocorrências neste minuto; baseline adaptativo %.1f/min, limite %.1f/min, aprendido em %d minutos. Aumento incomum exige revisão dos logs.", m.Counts[c], m.Mean[c], threshold, m.Samples), "local-anomaly", 10)
		}
	}
	return alerts
}
func (l *localAnalyzer) maintain(now time.Time, devices []Device) {
	allowed := map[string]bool{}
	for _, d := range devices {
		allowed[d.Name] = true
	}
	for name, m := range l.Devices {
		if !allowed[name] || now.Sub(m.LastSeen) > 2*time.Hour {
			delete(l.Devices, name)
			continue
		}
		m.advance(now)
	}
	for key, b := range l.Attempts {
		if now.Sub(b.First) > 5*time.Minute {
			delete(l.Attempts, key)
		}
	}
}
func (a *App) analysisSnapshot() analysisStatus {
	s := analysisStatus{Enabled: true, Mode: "Análise contínua local · estatística e diagnósticos", WarmupMinutes: analysisWarmup, DeviceLimit: analysisDeviceLimit, SourceLimit: analysisSourceLimit}
	if a.analyzer != nil {
		s.Devices = len(a.analyzer.Devices)
		s.Skipped = a.analyzer.Dropped
		for _, m := range a.analyzer.Devices {
			if m.Samples >= analysisWarmup {
				s.Ready++
			}
		}
	}
	return s
}
func (a *App) analyzeEvent(e Event) {
	if a.analyzer == nil {
		a.analyzer = newLocalAnalyzer()
	}
	for _, alert := range a.analyzer.observe(e) {
		if a.appendEvent(alert) && alert.Level >= a.cfg.MailMinLevel {
			select {
			case a.mailQ <- alert:
			default:
				a.mailStatus = "Fila de email cheia; notificação descartada"
			}
		}
	}
}
