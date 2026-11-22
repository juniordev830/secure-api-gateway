package gateway

import (
    "net/url"
    "strings"
    "testing"
)

func TestLocalhostUpstreamHostnameIsCaseInsensitive(t *testing.T) {
    token := strings.Repeat("s", 40)
    for _, raw := range []string{"http://localhost:9000", "http://LOCALHOST:9000", "http://LocalHost:9000"} {
        upstream, err := url.Parse(raw)
        if err != nil { t.Fatal(err) }
        if _, err := NewHandler(upstream, token); err != nil {
            t.Errorf("expected loopback hostname to be accepted: %s: %v", raw, err)
        }
    }
    upstream, _ := url.Parse("http://notlocalhost.example:9000")
    if _, err := NewHandler(upstream, token); err == nil {
        t.Fatal("non-loopback upstream must remain forbidden")
    }
}
