package gateway

import (
    "crypto/subtle"
    "errors"
    "net"
    "net/http"
    "net/http/httputil"
    "net/url"
    "path"
    "strings"
    "sync"
    "time"
)

const maxRequestBodyBytes int64 = 1 << 20
const maxRateLimitClients = 4096
const requestsPerMinute = 60

type window struct { since time.Time; count int }
type limiter struct { mu sync.Mutex; buckets map[string]window }

// Keep rate-limit bookkeeping bounded. New client addresses cannot displace
// active clients when the table is full. Expired buckets are recycled only
// when required, avoiding a full map scan for every normal request.
func (l *limiter) allow(key string) bool {
    l.mu.Lock()
    defer l.mu.Unlock()
    now := time.Now()
    if bucket, exists := l.buckets[key]; exists {
        if now.Sub(bucket.since) >= time.Minute {
            bucket = window{since: now}
        }
        if bucket.count >= requestsPerMinute { return false }
        bucket.count++
        l.buckets[key] = bucket
        return true
    }
    if len(l.buckets) >= maxRateLimitClients {
        for client, bucket := range l.buckets {
            if now.Sub(bucket.since) >= time.Minute { delete(l.buckets, client) }
        }
        if len(l.buckets) >= maxRateLimitClients { return false }
    }
    l.buckets[key] = window{since: now, count: 1}
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
        // A reverse proxy must not forward /api/../internal or encoded
        // separators that the upstream might normalize into other routes.
        // Check decoded Path; RawPath tracks an explicitly encoded slash.
        if path.Clean(req.URL.Path) != req.URL.Path ||
            strings.Contains(req.URL.Path, "\\") ||
            strings.Contains(strings.ToLower(req.URL.RawPath), "%2f") {
            http.Error(w, "non-canonical api path", http.StatusBadRequest)
            return
        }
        // Reject ambiguous Authorization fields rather than accepting the first value.
        authorization := req.Header.Values("Authorization")
        if len(authorization) != 1 || len(authorization[0]) > 8192 ||
            strings.ContainsAny(authorization[0], ",\r\n\t") {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        scheme, received, ok := strings.Cut(authorization[0], " ")
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
