//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func sampleHostHealth(ctx context.Context, dir string, previous HostCounters) (HostHealth, HostCounters) {
	health := HostHealth{Time: time.Now().UTC(), DiskPath: dir, Threshold: 90, Threads: []HostThread{}}
	current := HostCounters{Threads: map[string]uint64{}}
	var issues []string
	data, err := os.ReadFile("/proc/stat")
	if err == nil {
		current.Total, current.Idle, current.Cores, err = parseHostCPU(string(data))
	}
	if err != nil {
		issues = append(issues, "CPU indisponível")
	} else if previous.Total > 0 && current.Total > previous.Total && current.Idle >= previous.Idle {
		delta := current.Total - previous.Total
		idle := current.Idle - previous.Idle
		if idle <= delta {
			v := float64(delta-idle) / float64(delta) * 100
			health.CPU = &v
		}
	}
	data, err = os.ReadFile("/proc/meminfo")
	if err == nil {
		v, e := parseHostMemory(string(data))
		err = e
		if err == nil {
			health.Memory = &v
		}
	}
	if err != nil {
		issues = append(issues, "RAM indisponível")
	}
	var stat syscall.Statfs_t
	if err = syscall.Statfs(dir, &stat); err == nil && stat.Blocks > 0 && stat.Bavail <= stat.Blocks && stat.Bsize > 0 {
		v := float64(stat.Blocks-stat.Bavail) / float64(stat.Blocks) * 100
		health.Disk = &v
		total := uint64(stat.Blocks) * uint64(stat.Bsize)
		free := uint64(stat.Bavail) * uint64(stat.Bsize)
		health.DiskTotalBytes = &total
		health.DiskFreeBytes = &free
	} else {
		issues = append(issues, "Disco indisponível")
	}
	entries, _ := os.ReadDir("/proc")
	scanned := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		tasks, _ := os.ReadDir(filepath.Join("/proc", entry.Name(), "task"))
		for _, task := range tasks {
			if scanned >= 4096 || ctx.Err() != nil {
				break
			}
			scanned++
			tid, err := strconv.Atoi(task.Name())
			if err != nil {
				continue
			}
			b, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "task", task.Name(), "stat"))
			if err != nil {
				continue
			}
			raw := string(b)
			left, right := strings.Index(raw, "("), strings.LastIndex(raw, ")")
			if left < 0 || right <= left {
				continue
			}
			f := strings.Fields(raw[right+1:])
			if len(f) < 22 {
				continue
			}
			ut, _ := strconv.ParseUint(f[11], 10, 64)
			st, _ := strconv.ParseUint(f[12], 10, 64)
			rss, _ := strconv.ParseFloat(f[21], 64)
			ticks := ut + st
			key := strconv.Itoa(pid) + ":" + strconv.Itoa(tid) + ":" + f[19]
			current.Threads[key] = ticks
			cpu := 0.0
			if old, ok := previous.Threads[key]; ok && ticks >= old && current.Total > previous.Total {
				cpu = float64(ticks-old) / float64(current.Total-previous.Total) * float64(current.Cores) * 100
			}
			health.Threads = append(health.Threads, HostThread{PID: pid, TID: tid, Name: redact(raw[left+1 : right]), CPU: cpu, MemoryMB: rss * float64(os.Getpagesize()) / 1024 / 1024})
		}
	}
	sort.Slice(health.Threads, func(i, j int) bool {
		if health.Threads[i].CPU == health.Threads[j].CPU {
			return health.Threads[i].MemoryMB > health.Threads[j].MemoryMB
		}
		return health.Threads[i].CPU > health.Threads[j].CPU
	})
	if len(health.Threads) > 20 {
		health.Threads = health.Threads[:20]
	}
	for _, v := range []*float64{health.CPU, health.Memory, health.Disk} {
		if v != nil && *v >= 90 {
			health.High = true
		}
	}
	health.Error = strings.Join(issues, "; ")
	return health, current
}
