package main
import("io";"net/http";"net/http/httptest";"strings";"testing")
func TestAuditTLSBlackBoxUnauthorizedRequests(t *testing.T){
 a:=testApp(t);a.demo=false;a.nativeTLS=true;server:=httptest.NewUnstartedServer(a.routes());server.StartTLS();defer server.Close();a.origin=server.URL
 client:=server.Client();client.CheckRedirect=func(r *http.Request,via []*http.Request)error{return http.ErrUseLastResponse}
 attempts:=0
 for _,path:=range []string{"/api/snapshot","/api/accounts","/api/backups","/api/receivers","/api/critical-sounds","/api/ssh/sessions/not-owned"}{
  for _,forgery:=range []string{"cookie","bearer","forwarded"}{
   request,err:=http.NewRequest("GET",server.URL+path,nil);if err!=nil{t.Fatal(err)}
   switch forgery{case "cookie":request.Header.Set("Cookie","__Host-multipla_session=forged; multipla_session=forged");case "bearer":request.Header.Set("Authorization","Bearer forged");case "forwarded":request.Header.Set("X-Forwarded-For","127.0.0.1");request.Header.Set("X-Forwarded-Proto","https")}
   response,err:=client.Do(request);if err!=nil{t.Fatal(err)};io.Copy(io.Discard,response.Body);response.Body.Close();attempts++;if response.StatusCode!=401{t.Fatalf("%s %s accepted: %d",path,forgery,response.StatusCode)}
  }
 }
 request,_:=http.NewRequest("POST",server.URL+"/api/system/reboot",strings.NewReader(`{"confirm":"REINICIAR"}`));request.Header.Set("Origin",server.URL);request.Header.Set("X-CSRF-Token","forged");request.Header.Set("Content-Type","application/json");response,err:=client.Do(request);if err!=nil{t.Fatal(err)};defer response.Body.Close();if response.StatusCode!=401{t.Fatal("unauthorized reboot",response.StatusCode)};t.Logf("%d unauthorized requests rejected over real local TLS",attempts+1)
}
