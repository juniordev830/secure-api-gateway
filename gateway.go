package gateway

import (
    "crypto/subtle"
    "errors"
    "net"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strings"
    "sync"
    "time"
)

type window struct { since time.Time; count int }
type limiter struct { mu sync.Mutex; buckets map[string]window }
func (l *limiter) allow(key string) bool {
    l.mu.Lock(); defer l.mu.Unlock()
    now := time.Now()
    for k, b := range l.buckets { if now.Sub(b.since) >= time.Minute { delete(l.buckets, k) } }
    b, ok := l.buckets[key]
    if !ok { b = window{since: now} }
    if b.count >= 60 { return false }
    b.count++
    l.buckets[key] = b
    return true
}

func NewHandler(upstream *url.URL, token string) (http.Handler, error) {
    if len(token) < 32 { return nil, errors.New("GATEWAY_TOKEN requires 32+ characters") }
    if upstream == nil || upstream.Scheme != "http" || (upstream.Hostname() != "127.0.0.1" && upstream.Hostname() != "localhost") || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" {
        return nil, errors.New("upstream must be a fixed local HTTP URL")
    }
    proxy := httputil.NewSingleHostReverseProxy(upstream)
    originalDirector := proxy.Director
    proxy.Director = func(req *http.Request) {
        originalDirector(req)
        req.Header.Del("Authorization") // Never leak the gateway's token to upstream.
        req.Header.Del("Cookie")
    }
    rl := &limiter{buckets: make(map[string]window)}
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        if req.URL.Path == "/health" && req.Method == http.MethodGet {
            w.Header().Set("Content-Type", "application/json")
            w.Write([]byte(`{"status":"ok"}`)); return
        }
        if !strings.HasPrefix(req.URL.Path, "/api/") { http.NotFound(w, req); return }
        received := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
        if subtle.ConstantTimeCompare([]byte(received), []byte(token)) != 1 {
            http.Error(w, "unauthorized", http.StatusUnauthorized); return
        }
        ip, _, err := net.SplitHostPort(req.RemoteAddr); if err != nil { ip = req.RemoteAddr }
        if !rl.allow(ip) { http.Error(w, "rate limited", http.StatusTooManyRequests); return }
        proxy.ServeHTTP(w, req)
    }), nil
}
