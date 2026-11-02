package gateway
import (
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
)
func TestAuthorizedProxyAndHeaderIsolation(t *testing.T) {
    target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("Authorization") != "" { t.Error("gateway secret leaked upstream") }
        if r.Header.Get("Cookie") != "" { t.Error("cookie leaked upstream") }
        w.WriteHeader(204)
    })); defer target.Close()
    u,_ := url.Parse(target.URL)
    token := strings.Repeat("a", 40)
    h,err := NewHandler(u,token); if err!=nil {t.Fatal(err)}
    unauth:=httptest.NewRecorder(); h.ServeHTTP(unauth,httptest.NewRequest("GET","/api/jobs",nil))
    if unauth.Code!=401 {t.Fatalf("expected 401; got %d",unauth.Code)}
    req:=httptest.NewRequest("GET","/api/jobs",nil); req.Header.Set("Authorization","Bearer "+token);req.Header.Set("Cookie","session=secret")
    ok:=httptest.NewRecorder(); h.ServeHTTP(ok,req)
    if ok.Code!=204 {t.Fatalf("expected 204; got %d",ok.Code)}
}
func TestRejectsUnsafeSettings(t *testing.T) {
    u,_:=url.Parse("https://example.com")
    if _,err:=NewHandler(u,strings.Repeat("x",40));err==nil {t.Fatal("public upstream must be rejected")}
    u,_=url.Parse("http://127.0.0.1:9000")
    if _,err:=NewHandler(u,"weak");err==nil {t.Fatal("weak tokens rejected")}
}
