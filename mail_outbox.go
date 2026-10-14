package main

import (
	"fmt"
	"time"
)

type MailDelivery struct {
	Event     Event     `json:"event"`
	Attempts  int       `json:"attempts"`
	Next      time.Time `json:"next"`
	LastError string    `json:"last_error,omitempty"`
}

func (a *App) queueMailLocked(e Event) bool {
	if a.cfg.MailTo == "" || secret("GMAIL_USER") == "" || secret("GMAIL_APP_PASSWORD") == "" || a.demo {
		return true
	}
	if e.ID == "" {
		e.ID = token()
	}
	if !a.state.MailDelivered[e.ID].IsZero() {
		return true
	}
	for _, job := range a.state.MailOutbox {
		if job.Event.ID == e.ID {
			return true
		}
	}
	originCount := 0
	for _, job := range a.state.MailOutbox {
		if job.Event.SenderIP == e.SenderIP {
			originCount++
		}
	}
	if len(a.state.MailOutbox) >= 128 || originCount >= 32 {
		a.mailStatus = "Fila durável de email saturada"
		a.capacitySignal(a.mailStatus, e, false)
		return false
	}
	old := a.state.MailOutbox
	a.state.MailOutbox = append(append([]MailDelivery{}, old...), MailDelivery{Event: sanitizeEvent(e), Next: time.Now().UTC()})
	if a.persist() != nil {
		a.state.MailOutbox = old
		a.mailStatus = "Falha ao persistir notificação de email"
		a.capacitySignal(a.mailStatus, e, false)
		return false
	}
	return true
}
func (a *App) mailWorker() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case e, ok := <-a.mailQ:
			if !ok {
				return
			}
			a.mu.Lock()
			a.queueMailLocked(e)
			a.mu.Unlock()
		case <-ticker.C:
		}
		a.mu.Lock()
		index := -1
		for i, job := range a.state.MailOutbox {
			if !job.Next.After(time.Now()) {
				index = i
				break
			}
		}
		if index < 0 {
			a.mu.Unlock()
			continue
		}
		job := a.state.MailOutbox[index]
		to := a.cfg.MailTo
		a.mu.Unlock()
		var err error
		if to == "" || secret("GMAIL_USER") == "" || secret("GMAIL_APP_PASSWORD") == "" {
			err = fmt.Errorf("Gmail não configurado")
		} else {
			err = sendMail(to, job.Event)
		}
		a.mu.Lock()
		index = -1
		for i, pending := range a.state.MailOutbox {
			if pending.Event.ID == job.Event.ID {
				index = i
				job = pending
				break
			}
		}
		if index < 0 {
			a.mu.Unlock()
			continue
		}
		old := append([]MailDelivery{}, a.state.MailOutbox...)
		oldDead := append([]MailDelivery{}, a.state.MailDead...)
		if err == nil {
			a.state.MailOutbox = append(a.state.MailOutbox[:index], a.state.MailOutbox[index+1:]...)
			if a.state.MailDelivered == nil {
				a.state.MailDelivered = map[string]time.Time{}
			}
			a.state.MailDelivered[job.Event.ID] = time.Now().UTC()
			for id, at := range a.state.MailDelivered {
				if time.Since(at) > 24*time.Hour {
					delete(a.state.MailDelivered, id)
				}
			}
			if len(a.state.MailDelivered) > 512 {
				oldestID := ""
				var oldest time.Time
				for id, at := range a.state.MailDelivered {
					if oldest.IsZero() || at.Before(oldest) {
						oldestID = id
						oldest = at
					}
				}
				delete(a.state.MailDelivered, oldestID)
			}
			a.mailStatus = "Enviado em " + time.Now().Format(time.RFC3339)
		} else {
			job.Attempts++
			job.LastError = "Falha SMTP; confira conectividade, política e credenciais"
			job.Next = time.Now().Add(time.Duration(1<<min(job.Attempts, 6)) * time.Minute)
			if job.Attempts >= 6 {
				a.state.MailOutbox = append(a.state.MailOutbox[:index], a.state.MailOutbox[index+1:]...)
				a.state.MailDead = append(a.state.MailDead, job)
				if len(a.state.MailDead) > 128 {
					a.state.MailDead = a.state.MailDead[len(a.state.MailDead)-128:]
				}
				a.capacitySignal("Email esgotou tentativas; preservado na fila de falhas", job.Event, false)
			} else {
				a.state.MailOutbox[index] = job
			}
			a.mailStatus = job.LastError
		}
		a.audit("mailer", a.mailStatus)
		if a.persist() != nil {
			a.state.MailOutbox = old
			a.state.MailDead = oldDead
			delete(a.state.MailDelivered, job.Event.ID)
			a.capacitySignal("Falha ao persistir estado SMTP; entrega pode repetir", job.Event, false)
		}
		a.mu.Unlock()
	}
}
