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

func TestProxyIgnoresSpoofedForwardingHeaders(t *testing.T) {
    upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        if got := req.Header.Get("Authorization"); got != "" {
            t.Errorf("secret leaked to upstream: %q", got)
        }
        if got := req.Header.Get("Cookie"); got != "" {
            t.Errorf("cookie leaked to upstream: %q", got)
        }
        if got := req.Header.Get("Forwarded"); got != "" {
            t.Errorf("untrusted Forwarded leaked: %q", got)
        }
        if got := req.Header.Get("X-Real-IP"); got != "" {
            t.Errorf("untrusted X-Real-IP leaked: %q", got)
        }
        if got := req.Header.Get("X-Forwarded-For"); got != "192.0.2.1" {
            t.Errorf("forwarded client IP should be the socket peer, got %q", got)
        }
        if got := req.Header.Get("X-Forwarded-Host"); got != "gateway.example" {
            t.Errorf("expected true incoming Host, got %q", got)
        }
        if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
            t.Errorf("expected true scheme, got %q", got)
        }
        if req.URL.Path != "/api/jobs" || req.URL.RawQuery != "limit=3" {
            t.Errorf("unexpected proxied URL %s", req.URL.String())
        }
        w.WriteHeader(http.StatusNoContent)
    }))
    defer upstreamServer.Close()
    upstream, err := url.Parse(upstreamServer.URL)
    if err != nil { t.Fatal(err) }
    token := strings.Repeat("b", 40)
    gateway, err := NewHandler(upstream, token)
    if err != nil { t.Fatal(err) }
    request := httptest.NewRequest(http.MethodGet, "http://gateway.example/api/jobs?limit=3", nil)
    request.RemoteAddr = "192.0.2.1:1234"
    request.Header.Set("Authorization", "Bearer "+token)
    request.Header.Set("Cookie", "session=secret")
    request.Header.Set("Forwarded", "for=203.0.113.10;proto=https")
    request.Header.Set("X-Real-IP", "203.0.113.10")
    request.Header.Set("X-Forwarded-For", "203.0.113.10")
    request.Header.Set("X-Forwarded-Host", "attacker.example")
    request.Header.Set("X-Forwarded-Proto", "https")
    response := httptest.NewRecorder()
    gateway.ServeHTTP(response, request)
    if response.Code != http.StatusNoContent {
        t.Fatalf("expected 204, got %d: %s", response.Code, response.Body.String())
    }
}
