package gateway

import (
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
)

// A direct http.Handler call may supply a nil Body even though net/http servers normalize it.
func TestProxyHandlesNilRequestBody(t *testing.T) {
    reached := false
    upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        reached = true
        if r.ContentLength != 0 {
            t.Errorf("expected empty body, got content length %d", r.ContentLength)
        }
        w.WriteHeader(http.StatusNoContent)
    }))
    defer upstreamServer.Close()

    upstream, err := url.Parse(upstreamServer.URL)
    if err != nil { t.Fatal(err) }
    token := strings.Repeat("n", 40)
    handler, err := NewHandler(upstream, token)
    if err != nil { t.Fatal(err) }

    request := httptest.NewRequest(http.MethodPost, "/api/empty", nil)
    request.Body = nil
    request.Header.Set("Authorization", "Bearer "+token)
    recorder := httptest.NewRecorder()
    handler.ServeHTTP(recorder, request)
    if recorder.Code != http.StatusNoContent || !reached {
        t.Fatalf("expected successful forwarding of empty body; status=%d reached=%v", recorder.Code, reached)
    }
}
