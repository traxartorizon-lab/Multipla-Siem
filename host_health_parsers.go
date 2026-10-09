package main

import (
	"fmt"
	"strconv"
	"strings"
)

func parseHostCPU(data string) (uint64, uint64, int, error) {
	var total, idle uint64
	cores := 0
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "cpu" {
			if len(f) < 5 {
				return 0, 0, 0, fmt.Errorf("CPU indisponível")
			}
			for i, v := range f[1:] {
				if i >= 8 {
					break
				}
				n, err := strconv.ParseUint(v, 10, 64)
				if err != nil {
					return 0, 0, 0, err
				}
				total += n
				if i == 3 || i == 4 {
					idle += n
				}
			}
		} else if strings.HasPrefix(f[0], "cpu") {
			cores++
		}
	}
	if total == 0 {
		return 0, 0, 0, fmt.Errorf("CPU indisponível")
	}
	return total, idle, cores, nil
}
func parseHostMemory(data string) (float64, error) {
	values := map[string]float64{}
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			v, err := strconv.ParseFloat(f[1], 64)
			if err == nil {
				values[strings.TrimSuffix(f[0], ":")] = v
			}
		}
	}
	total := values["MemTotal"]
	available, ok := values["MemAvailable"]
	if !ok || total <= 0 || available > total {
		return 0, fmt.Errorf("RAM indisponível")
	}
	return (total - available) / total * 100, nil
}
