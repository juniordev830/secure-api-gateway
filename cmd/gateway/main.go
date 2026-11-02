package main
import (
    "log"
    "net/http"
    "net/url"
    "os"
    gateway "example.com/secure-api-gateway"
)
func main() {
    target := os.Getenv("GATEWAY_UPSTREAM")
    if target == "" { target = "http://127.0.0.1:9000" }
    upstream, err := url.Parse(target); if err != nil { log.Fatal(err) }
    handler, err := gateway.NewHandler(upstream, os.Getenv("GATEWAY_TOKEN")); if err != nil { log.Fatal(err) }
    log.Println("Gateway listening on 127.0.0.1:8080")
    log.Fatal(http.ListenAndServe("127.0.0.1:8080", handler))
}
