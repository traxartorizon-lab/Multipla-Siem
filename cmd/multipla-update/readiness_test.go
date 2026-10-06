package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReadinessRetriesSlowStartupAndStopsAtDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	attempts := 0
	err := waitForPanel(ctx, time.Millisecond, func(context.Context) error {
		attempts++
		if attempts < 4 {
			return errors.New("connection refused")
		}
		return nil
	})
	if err != nil || attempts != 4 {
		t.Fatal("slow startup rolled back prematurely", err, attempts)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel2()
	err = waitForPanel(ctx2, time.Millisecond, func(context.Context) error { return errors.New("TLS certificate mismatch") })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("failure did not expire", err)
	}
}
