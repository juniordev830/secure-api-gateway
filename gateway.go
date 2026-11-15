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

const (
    maxRequestBodyBytes int64 = 1 << 20
    rateLimitWindow = time.Minute
    rateLimitCleanupInterval = 30 * time.Second
    maxRateLimitBuckets = 4096
)

type window struct { since time.Time; count int }
type limiter struct {
    mu sync.Mutex
    buckets map[string]window
    lastCleanup time.Time
}

func (l *limiter) allow(key string) bool {
    l.mu.Lock()
    defer l.mu.Unlock()

    now := time.Now()
    if l.buckets == nil {
        l.buckets = make(map[string]window)
    }

    // Prune stale entries periodically instead of scanning the map on every request.
    if l.lastCleanup.IsZero() || now.Sub(l.lastCleanup) >= rateLimitCleanupInterval {
        for client, bucket := range l.buckets {
            if now.Sub(bucket.since) >= rateLimitWindow {
                delete(l.buckets, client)
            }
        }
        l.lastCleanup = now
    }

    bucket, exists := l.buckets[key]
    if !exists {
        // Fail closed when full: do not allocate unbounded state for unique source IPs.
        if len(l.buckets) >= maxRateLimitBuckets {
            return false
        }
        bucket = window{since: now}
    } else if now.Sub(bucket.since) >= rateLimitWindow {
        // Reuse this client's expired slot even if global cleanup is not due.
        bucket = window{since: now}
    }

    if bucket.count >= 60 {
        return false
    }
    bucket.count++
    l.buckets[key] = bucket
    return true
}

func NewHandler(upstream *url.URL, token string) (http.Handler, error) {
    if len(token) < 32 { return nil, errors.New("GATEWAY_TOKEN requires 32+ characters") }
    if upstream == nil || upstream.Scheme != "http" || (upstream.Hostname() != "127.0.0.1" && upstream.Hostname() != "localhost") || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" {
        return nil, errors.New("upstream must be a fixed local HTTP URL")
    }
    // Rewrite discards untrusted X-Forwarded-* headers before deriving trusted
    // forwarding metadata from the actual incoming request.
    proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
        pr.SetURL(upstream)
        pr.Out.Header.Del("Authorization") // Never leak the gateway token.
        pr.Out.Header.Del("Proxy-Authorization") // Do not forward client proxy credentials.
        pr.Out.Header.Del("Cookie")
        pr.Out.Header.Del("Forwarded")
        pr.Out.Header.Del("X-Real-IP")
        // ReverseProxy removes the standard forwarding trio, but custom
        // X-Forwarded-* values may still be copied from the client. An
        // upstream must never mistake those values for gateway assertions.
        for name := range pr.Out.Header {
            if strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
                delete(pr.Out.Header, name)
            }
        }
        pr.SetXForwarded()
    }}
    rl := &limiter{buckets: make(map[string]window)}
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        if req.URL.Path == "/health" && req.Method == http.MethodGet {
            w.Header().Set("Content-Type", "application/json")
            w.Write([]byte(`{"status":"ok"}`)); return
        }
        if !strings.HasPrefix(req.URL.Path, "/api/") { http.NotFound(w, req); return }
        // Reject duplicate Authorization values; Header.Get only reads the first.
        authorizations := req.Header.Values("Authorization")
        if len(authorizations) != 1 {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        scheme, received, ok := strings.Cut(authorizations[0], " ")
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
