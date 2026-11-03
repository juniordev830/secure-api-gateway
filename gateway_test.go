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

func TestRejectsOversizedRequestBody(t *testing.T) {
    target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusNoContent)
    }))
    defer target.Close()
    upstream, err := url.Parse(target.URL)
    if err != nil {
        t.Fatal(err)
    }
    token := strings.Repeat("a", 40)
    handler, err := NewHandler(upstream, token)
    if err != nil {
        t.Fatal(err)
    }
    request := httptest.NewRequest(http.MethodPost, "/api/upload",
        strings.NewReader(strings.Repeat("x", int(maxRequestBodyBytes+1))))
    request.Header.Set("Authorization", "Bearer "+token)
    response := httptest.NewRecorder()
    handler.ServeHTTP(response, request)
    if response.Code != http.StatusRequestEntityTooLarge {
        t.Fatalf("expected 413, got %d", response.Code)
    }
}

func TestRequiresBearerScheme(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	upstream, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 40)
	handler, err := NewHandler(upstream, token)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, header string
		want         int
	}{
		{"raw token", token, http.StatusUnauthorized},
		{"different scheme", "Basic " + token, http.StatusUnauthorized},
		{"empty bearer token", "Bearer ", http.StatusUnauthorized},
		{"case insensitive scheme", "bearer " + token, http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/jobs", nil)
			request.Header.Set("Authorization", tc.header)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Errorf("expected status %d, got %d", tc.want, response.Code)
			}
		})
	}
}

func TestDropsSpoofedForwardingHeaders(t *testing.T) {
    expectedHost := ""
    target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Host != expectedHost {
            t.Errorf("upstream Host = %q; want %q", r.Host, expectedHost)
        }
        if got := r.Header.Get("X-Forwarded-For"); got != "192.0.2.1" {
            t.Errorf("X-Forwarded-For = %q; want real client IP", got)
        }
        for _, key := range []string{
            "Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto",
            "X-Forwarded-Port", "X-Forwarded-Server", "X-Real-IP",
        } {
            if got := r.Header.Get(key); got != "" {
                t.Errorf("%s leaked: %q", key, got)
            }
        }
        w.WriteHeader(http.StatusNoContent)
    }))
    defer target.Close()
    upstream, err := url.Parse(target.URL)
    if err != nil { t.Fatal(err) }
    expectedHost = upstream.Host
    token := strings.Repeat("a", 40)
    handler, err := NewHandler(upstream, token)
    if err != nil { t.Fatal(err) }
    req := httptest.NewRequest(http.MethodGet, "/api/jobs", nil)
    req.Host = "attacker.example"
    req.Header.Set("Authorization", "Bearer " + token)
    for _, key := range []string{
        "Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Server", "X-Real-IP",
    } {
        req.Header.Set(key, "spoofed")
    }
    res := httptest.NewRecorder()
    handler.ServeHTTP(res, req)
    if res.Code != http.StatusNoContent {
        t.Fatalf("unexpected status: %d", res.Code)
    }
}
