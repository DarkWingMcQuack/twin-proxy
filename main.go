package main

import (
	"log"
	"net/http"
	"net"
	"os"
	"flag"
	"os/signal"
	"syscall"
	"math/rand"
	"time"

	"github.com/AdguardTeam/gomitmproxy"

)
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}


func main() {
	rand.Seed(time.Now().UnixNano())

	port := flag.Int("p", 0, "port of the proxy")
	user := flag.String("user", "", "username for the proxy basic auth")
	pwd := flag.String("password", "", "password for the proxy basic auth")

	flag.Parse()

	if *user == "" {
		*user = randSeq(10)
		log.Printf("no user given using: %s", *user)
	}

	if *pwd == "" {
		*pwd = randSeq(10)
		log.Printf("no password given using: %s", *pwd)
	}

	if *port == 0 {
		*port = 8080
		log.Printf("no port given using: %d", *port)
	}


	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: *port,
		},
		OnRequest:  onRequest,
		OnResponse: onResponse,
		Username: *user,
		Password: *pwd,
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
