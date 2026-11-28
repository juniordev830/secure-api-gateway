package gateway

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	maxRequestBodyBytes      int64 = 1 << 20
	rateLimitWindow                = time.Minute
	rateLimitCleanupInterval       = 30 * time.Second
	maxRateLimitBuckets            = 4096
	maxInFlight                    = 32
)

type window struct {
	since time.Time
	count int
}
type limiter struct {
	mu          sync.Mutex
	buckets     map[string]window
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
	if len(token) < 32 || len(token) > 4096 || strings.TrimSpace(token) != token ||
		strings.IndexFunc(token, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return nil, errors.New("GATEWAY_TOKEN must have 32-4096 characters without controls or edge whitespace")
	}
	if upstream == nil || upstream.Scheme != "http" || upstream.Opaque != "" ||
		(upstream.Hostname() != "127.0.0.1" && !strings.EqualFold(upstream.Hostname(), "localhost")) ||
		upstream.User != nil || upstream.RawQuery != "" || upstream.ForceQuery || upstream.Fragment != "" {
		return nil, errors.New("upstream must be a fixed local HTTP URL")
	}
	target := *upstream
	transport := &http.Transport{
		DialContext:            (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:           maxInFlight,
		MaxIdleConnsPerHost:    maxInFlight,
		MaxConnsPerHost:        maxInFlight,
		IdleConnTimeout:        30 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	// Rewrite discards untrusted X-Forwarded-* headers before deriving trusted
	// forwarding metadata from the actual incoming request.
	proxy := &httputil.ReverseProxy{Transport: transport, Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(&target)
		pr.Out.Header.Del("Authorization")       // Never leak the gateway token.
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
	inFlight := make(chan struct{}, maxInFlight)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/health" && req.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if !strings.HasPrefix(req.URL.Path, "/api/") {
			http.NotFound(w, req)
			return
		}
		canonical := path.Clean(req.URL.Path)
		escaped := strings.ToLower(req.URL.EscapedPath())
		if canonical != strings.TrimSuffix(req.URL.Path, "/") ||
			strings.ContainsAny(req.URL.Path, "\\%") || strings.Contains(escaped, "%2f") ||
			req.Method == http.MethodConnect || req.Header.Get("Upgrade") != "" {
			http.Error(w, "invalid API route", http.StatusBadRequest)
			return
		}
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			ip = req.RemoteAddr
		}
		if !rl.allow(ip) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		// Reject duplicate Authorization values; Header.Get only reads the first.
		authorizations := req.Header.Values("Authorization")
		if len(authorizations) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		scheme, received, ok := strings.Cut(authorizations[0], " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(received), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if req.ContentLength > maxRequestBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		select {
		case inFlight <- struct{}{}:
			defer func() { <-inFlight }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "gateway busy", http.StatusServiceUnavailable)
			return
		}
		if req.Body == nil {
			req.Body = http.NoBody
		}
		// Reject oversized chunked/unknown-length bodies before proxying any bytes.
		// Otherwise an upstream could receive a partial request before MaxBytesReader fails.
		body, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBodyBytes+1))
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxRequestBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		forwarded := req.Clone(req.Context())
		forwarded.Body = http.NoBody
		if len(body) > 0 {
			forwarded.Body = io.NopCloser(bytes.NewReader(body))
		}
		forwarded.ContentLength = int64(len(body))
		forwarded.TransferEncoding = nil
		forwarded.Trailer = nil
		proxy.ServeHTTP(w, forwarded)
	}), nil
}
