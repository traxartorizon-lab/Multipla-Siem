package main

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"
)

type SystemNotification struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Severity string    `json:"severity"`
	EventID  string    `json:"event_id,omitempty"`
}
type HostThread struct {
	PID      int     `json:"pid"`
	TID      int     `json:"tid"`
	Name     string  `json:"name"`
	CPU      float64 `json:"cpu"`
	MemoryMB float64 `json:"memory_mb"`
}
type HostHealth struct {
	Time      time.Time    `json:"time"`
	CPU       *float64     `json:"cpu,omitempty"`
	Memory    *float64     `json:"memory,omitempty"`
	Disk      *float64     `json:"disk,omitempty"`
	DiskPath  string       `json:"disk_path"`
	Threads   []HostThread `json:"threads"`
	Error     string       `json:"error,omitempty"`
	High      bool         `json:"high"`
	Threshold int          `json:"threshold"`
}
type HostCounters struct {
	Total   uint64
	Idle    uint64
	Cores   int
	Threads map[string]uint64
}

func (a *App) addNotification(n SystemNotification) {
	for _, old := range a.state.Notifications {
		if old.ID == n.ID {
			return
		}
	}
	n.Title = redact(n.Title)
	n.Detail = redact(n.Detail)
	a.state.Notifications = append(a.state.Notifications, n)
	if len(a.state.Notifications) > 200 {
		a.state.Notifications = a.state.Notifications[len(a.state.Notifications)-200:]
	}
	a.notificationDirty = true
}
func (a *App) notifyCriticalEvent(e Event) {
	if e.Level < 12 || (e.Review != nil && e.Review.Status == "false_positive") {
		return
	}
	title := e.Rule
	if title == "" {
		title = "Evento crítico"
	}
	a.addNotification(SystemNotification{ID: "event-" + e.ID, Time: time.Now().UTC(), Title: title, Detail: e.Device + " · " + e.SourceIP, Severity: "critical", EventID: e.ID})
}
func (a *App) updateHostConditions(health HostHealth) {
	if a.state.HostConditions == nil {
		a.state.HostConditions = map[string]bool{}
	}
	conditions := map[string]bool{}
	for key, value := range map[string]*float64{"CPU": health.CPU, "RAM": health.Memory, "Disco": health.Disk} {
		if value != nil {
			conditions[key] = *value >= 90 || (a.state.HostConditions[key] && *value >= 85)
		}
	}
	if health.Error != "" {
		conditions["Coleta do servidor"] = true
	} else {
		conditions["Coleta do servidor"] = false
	}
	if a.storageError != "" {
		conditions["Armazenamento do SIEM"] = true
	} else {
		conditions["Armazenamento do SIEM"] = false
	}
	for key, high := range conditions {
		previous := a.state.HostConditions[key]
		if high == previous {
			continue
		}
		a.state.HostConditions[key] = high
		title := key + " normalizado"
		severity := "info"
		detail := "Condição normalizada após uma medição anterior de alerta."
		if high {
			title = key + " exige atenção"
			severity = "critical"
			detail = "Uso de recurso atingiu 90% ou a medição está indisponível."
			if key == "Armazenamento do SIEM" {
				detail = a.storageError
			}
			if key == "Coleta do servidor" {
				detail = health.Error
			}
		}
		a.addNotification(SystemNotification{ID: token(), Time: health.Time, Title: title, Detail: detail, Severity: severity})
	}
}
func (a *App) hostHealthWorker() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		a.mu.Lock()
		previous := a.hostPrevious
		dir := a.cfg.DataDir
		demo := a.demo
		a.mu.Unlock()
		health, counters := sampleHostHealth(ctx, dir, previous)
		cancel()
		if !demo {
			a.mu.Lock()
			a.hostHealth = health
			a.hostPrevious = counters
			a.updateHostConditions(health)
			if a.notificationDirty {
				if a.persist() == nil {
					a.notificationDirty = false
				} else {
					a.storageError = "Falha ao salvar notificações"
				}
			}
			a.mu.Unlock()
		}
		time.Sleep(5 * time.Second)
	}
}
func notificationView(all []SystemNotification, cleared time.Time) ([]SystemNotification, int) {
	result := append([]SystemNotification{}, all...)
	sort.Slice(result, func(i, j int) bool { return result[i].Time.After(result[j].Time) })
	unread := 0
	for _, n := range result {
		if n.Time.After(cleared) {
			unread++
		}
	}
	return result, unread
}
func (a *App) registerHostHealthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/system/health", a.auth(func(w http.ResponseWriter, r *http.Request) {
		session, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		health := a.hostHealth
		_, unread := notificationView(a.state.Notifications, a.state.NotificationsCleared[strings.ToLower(session.Email)])
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"health": health, "unread": unread})
	}))
	mux.HandleFunc("GET /api/notifications", a.auth(func(w http.ResponseWriter, r *http.Request) {
		session, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		cleared := a.state.NotificationsCleared[strings.ToLower(session.Email)]
		all, unread := notificationView(a.state.Notifications, cleared)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"notifications": all, "unread": unread, "cleared": cleared, "limit": 200})
	}))
	mux.HandleFunc("POST /api/notifications/clear", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Through time.Time `json:"through"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.Through.IsZero() || body.Through.After(time.Now().UTC()) {
			http.Error(w, "Instante inválido", 400)
			return
		}
		session, _ := a.session(r)
		email := strings.ToLower(session.Email)
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.state.NotificationsCleared == nil {
			a.state.NotificationsCleared = map[string]time.Time{}
		}
		if len(a.state.NotificationsCleared) >= 102 {
			if _, ok := a.state.NotificationsCleared[email]; !ok {
				http.Error(w, "Limite de contas", 400)
				return
			}
		}
		old := a.state.NotificationsCleared[email]
		if body.Through.Before(old) {
			body.Through = old
		}
		a.state.NotificationsCleared[email] = body.Through
		if err := a.persist(); err != nil {
			a.state.NotificationsCleared[email] = old
			http.Error(w, "Falha ao limpar notificações", 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
