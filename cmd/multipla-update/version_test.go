package main

import (
 "os"
 "strings"
 "testing"
)

func TestUpdaterVersionMatchesProductRelease(t *testing.T) {
 raw,err:=os.ReadFile("../../VERSION")
 if err!=nil {t.Fatal(err)}
 if strings.TrimSpace(string(raw))!=updaterVersion {t.Fatalf("updater %s differs from product %s",updaterVersion,strings.TrimSpace(string(raw)))}
}
