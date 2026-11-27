package main

import (
	"net/http"
	"testing"
	"time"
)

func TestHTTPServerUsesFiniteTimeoutsAndHeaderLimit(t *testing.T) {
	server := newHTTPServer("127.0.0.1:0", http.NotFoundHandler())

	if server.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("unexpected ReadHeaderTimeout: %s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 15*time.Second {
		t.Fatalf("unexpected ReadTimeout: %s", server.ReadTimeout)
	}
	if server.WriteTimeout != 60*time.Second {
		t.Fatalf("unexpected WriteTimeout: %s", server.WriteTimeout)
	}
	if server.IdleTimeout != 60*time.Second {
		t.Fatalf("unexpected IdleTimeout: %s", server.IdleTimeout)
	}
	if server.MaxHeaderBytes <= 0 {
		t.Fatal("MaxHeaderBytes must be bounded")
	}
}
