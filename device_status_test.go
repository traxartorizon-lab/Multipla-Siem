package main

import "testing"

func TestTailscalePresenceTracksOnlineAndOfflinePeers(t *testing.T) {
	peers, err := tailscalePeerPresence([]byte(`{"BackendState":"Running","Peer":{"a":{"Online":true,"TailscaleIPs":["100.83.245.103","fd7a::1"]},"b":{"Online":false,"TailscaleIPs":["100.90.1.2"]}}}`))
	if err != nil || !peers["100.83.245.103"] || !peers["fd7a::1"] || peers["100.90.1.2"] {
		t.Fatal("incorrect peer presence", peers, err)
	}
	if _, ok := peers["100.90.1.2"]; !ok {
		t.Fatal("offline peer omitted")
	}
	if _, ok := peers["192.168.1.1"]; ok {
		t.Fatal("invented LAN presence")
	}
	if peers, err = tailscalePeerPresence([]byte(`{"BackendState":"Stopped","Peer":{}}`)); err != nil || len(peers) != 0 {
		t.Fatal("stopped daemon reported peers")
	}
	if _, err = tailscalePeerPresence([]byte(`invalid`)); err == nil {
		t.Fatal("invalid status accepted")
	}
}
