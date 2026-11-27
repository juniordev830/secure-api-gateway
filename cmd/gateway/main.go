package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	gateway "example.com/secure-api-gateway"
)

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func main() {
	target := os.Getenv("GATEWAY_UPSTREAM")
	if target == "" {
		target = "http://127.0.0.1:9000"
	}
	upstream, err := url.Parse(target)
	if err != nil {
		log.Fatal(err)
	}
	handler, err := gateway.NewHandler(upstream, os.Getenv("GATEWAY_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Gateway listening on 127.0.0.1:8080")
	log.Fatal(newHTTPServer("127.0.0.1:8080", handler).ListenAndServe())
}
