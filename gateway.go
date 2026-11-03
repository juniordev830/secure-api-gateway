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

const maxRequestBodyBytes int64 = 1 << 20

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
        req.Host = upstream.Host // The upstream must never see a client-controlled Host.
        req.Header.Del("Authorization") // Never leak the gateway's token to upstream.
        req.Header.Del("Cookie")
        // Prevent callers from impersonating another client or public origin.
        // ReverseProxy adds a fresh X-Forwarded-For from req.RemoteAddr later.
        for _, header := range []string{
            "Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
            "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Server",
            "X-Real-IP",
        } {
            req.Header.Del(header)
        }
    }
    rl := &limiter{buckets: make(map[string]window)}
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        if req.URL.Path == "/health" && req.Method == http.MethodGet {
            w.Header().Set("Content-Type", "application/json")
            w.Write([]byte(`{"status":"ok"}`)); return
        }
        if !strings.HasPrefix(req.URL.Path, "/api/") { http.NotFound(w, req); return }
        scheme, received, ok := strings.Cut(req.Header.Get("Authorization"), " ")
        if !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(received), []byte(token)) != 1 {
            http.Error(w, "unauthorized", http.StatusUnauthorized); return
        }
        if req.ContentLength > maxRequestBodyBytes {
            http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
            return
        }
        req.Body = http.MaxBytesReader(w, req.Body, maxRequestBodyBytes)
        ip, _, err := net.SplitHostPort(req.RemoteAddr); if err != nil { ip = req.RemoteAddr }
        if !rl.allow(ip) { http.Error(w, "rate limited", http.StatusTooManyRequests); return }
        proxy.ServeHTTP(w, req)
    }), nil
}
