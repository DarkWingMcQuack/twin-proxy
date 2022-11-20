package main

import (
	"log"
	"net/http"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/AdguardTeam/gomitmproxy"

)

func main() {
	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: 8080,
		},
		OnRequest:  onRequest,
		OnResponse: onResponse,
		Username: "user",
		Password: "pass",
	})

	err := proxy.Start()
	if err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Clean up
	proxy.Close()
}

func onRequest(session *gomitmproxy.Session) (*http.Request, *http.Response) {
	req := session.Request()
	log.Printf("Request: %s %s", req.Method, req.URL.String())
	return nil, nil
}

func onResponse(session *gomitmproxy.Session) *http.Response {
	log.Printf("Response: %s: %s", session.Request().URL.String(), session.Response().Status)
	return session.Response()
}
