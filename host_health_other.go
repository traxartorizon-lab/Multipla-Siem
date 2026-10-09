//go:build !linux

package main

import (
	"context"
	"time"
)

func sampleHostHealth(ctx context.Context, dir string, previous HostCounters) (HostHealth, HostCounters) {
	return HostHealth{Time: time.Now().UTC(), DiskPath: dir, Threshold: 90, Error: "Monitoramento do servidor disponível na instalação Linux", Threads: []HostThread{}}, HostCounters{}
}
