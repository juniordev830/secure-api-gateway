package gateway

import (
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
)

func TestBearerSchemeAllowsMultipleSpaces(t *testing.T) {
    upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusNoContent)
    }))
    defer upstreamServer.Close()
    upstream, _ := url.Parse(upstreamServer.URL)
    token := strings.Repeat("v", 40)
    handler, err := NewHandler(upstream, token)
    if err != nil { t.Fatal(err) }
    cases := []struct{ header string; want int }{
        {"Bearer " + token, http.StatusNoContent},
        {"Bearer  " + token, http.StatusNoContent},
        {"bearer    " + token, http.StatusNoContent},
        {"Bearer " + token + " ", http.StatusUnauthorized},
    }
    for _, tc := range cases {
        request := httptest.NewRequest(http.MethodGet, "/api/jobs", nil)
        request.Header.Set("Authorization", tc.header)
        response := httptest.NewRecorder()
        handler.ServeHTTP(response, request)
        if response.Code != tc.want {
            t.Errorf("header len=%d: got %d, want %d", len(tc.header), response.Code, tc.want)
        }
    }
}
