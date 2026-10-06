package main

import (
 "net/http/httptest"
 "regexp"
 "strings"
 "testing"
)

func TestPageReferencedAssetsServedByActualRoutes(t *testing.T) {
 a:=testApp(t)
 page,err:=assets.ReadFile("web/index.html")
 if err!=nil { t.Fatal(err) }
 refs:=regexp.MustCompile(`(?:src|href)="(/[^"?#]+)(?:\?[^"#]*)?"`).FindAllStringSubmatch(string(page),-1)
 if len(refs)<10 { t.Fatal("asset references missing") }
 for _,ref:=range refs {
  path:=ref[1]
  if !strings.HasSuffix(path,".js") && !strings.HasSuffix(path,".css") { continue }
  w:=httptest.NewRecorder()
  a.routes().ServeHTTP(w,httptest.NewRequest("GET",path,nil))
  expected,err:=assets.ReadFile("web"+path)
  if err!=nil { t.Fatal(err) }
  kind:="text/javascript";if strings.HasSuffix(path,".css") {kind="text/css"}
  if w.Code!=200 || w.Header().Get("Content-Type")!=kind || w.Body.String()!=string(expected) {t.Fatalf("asset %s unavailable: status=%d type=%s",path,w.Code,w.Header().Get("Content-Type"))}
 }
}
