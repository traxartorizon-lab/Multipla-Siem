package main

import "strings"

// eventClientIndex is built while a.mu is held. Conflicting registrations are
// deliberately left unassigned rather than mixing clients in a filter.
func (a *App) eventClientIndex() map[string]string {
	index := map[string]string{}
	add := func(name, ip, client string) {
		client = strings.TrimSpace(client)
		if client == "" {
			return
		}
		for _, key := range []string{"name:" + name, "ip:" + ip} {
			if key == "name:" || key == "ip:" {
				continue
			}
			if old, exists := index[key]; exists && old != client {
				index[key] = ""
			} else if !exists {
				index[key] = client
			}
		}
	}
	for _, d := range a.cfg.Devices {
		add(d.Name, d.IP, d.Client)
	}
	for _, d := range a.state.NetworkEquipment {
		add(d.Name, d.IP, d.Client)
	}
	return index
}

func clientForEvent(index map[string]string, event Event) string {
	if client, exists := index["name:"+event.Device]; exists {
		return client
	}
	return index["ip:"+event.SenderIP]
}
