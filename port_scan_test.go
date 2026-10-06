package main

import "testing"

func TestValidateScanPorts(t *testing.T) {
	for _, v := range []string{"", "22", "22,80,443", "1-1024", "65535"} {
		if err := validateScanPorts(v); err != nil {
			t.Fatalf("valid %q: %v", v, err)
		}
	}
	for _, v := range []string{"0", "65536", "1-1025", "22;id", "-p80", "80-22", "22,", "1-1024,65535"} {
		if validateScanPorts(v) == nil {
			t.Fatalf("accepted invalid %q", v)
		}
	}
}
