package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"time"
)

func tailscalePeerPresence(data []byte) (map[string]bool, error) {
	var status struct {
		BackendState string
		Peer         map[string]struct {
			Online       bool
			TailscaleIPs []string
		}
	}
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}
	peers := map[string]bool{}
	if status.BackendState != "Running" {
		return peers, nil
	}
	for _, peer := range status.Peer {
		for _, ip := range peer.TailscaleIPs {
			peers[ip] = peer.Online
		}
	}
	return peers, nil
}

func (a *App) devicePresenceWorker() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		data, err := exec.CommandContext(ctx, "tailscale", "status", "--json").Output()
		cancel()
		var peers map[string]bool
		if err == nil {
			peers, err = tailscalePeerPresence(data)
		}
		a.mu.Lock()
		if err == nil {
			a.devicePresence = peers
		} else {
			a.devicePresence = nil
		}
		a.mu.Unlock()
		time.Sleep(15 * time.Second)
	}
}
