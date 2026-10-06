package main

import (
	"context"
	"fmt"
	"time"
)

// Keep TLS validation and automatic rollback, but allow slow journal replay.
func waitHealthy() error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return waitForPanel(ctx, 2*time.Second, healthyContext)
}

func waitForPanel(ctx context.Context, interval time.Duration, probe func(context.Context) error) error {
	var last error
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("prazo para iniciar o painel esgotado: %v: %w", last, ctx.Err())
		}
		if last = probe(ctx); last == nil {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("prazo para iniciar o painel esgotado: %v: %w", last, ctx.Err())
		case <-timer.C:
		}
	}
}
