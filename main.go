package main

import (
	"log"
	"net/http"
	"io/ioutil"
	"strconv"
	"net"
	"os"
	"flag"
	"os/signal"
	"syscall"
	"math/rand"
	"time"

	"github.com/AdguardTeam/gomitmproxy"
	"github.com/phayes/freeport"


)
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func getPort() int {
	var port int

	buf, err := ioutil.ReadFile("port.txt")

	if err != nil {
		port, err = freeport.GetFreePort()
		if err != nil {
			panic(err)
		}
	}else{
		content := string(buf)
		port, err = strconv.Atoi(content)
		if err != nil {
			panic(err)
		}
	}

	f, err := os.Create("port.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	f.Write([]byte(strconv.Itoa(port)))

	return port
}


func main() {
	rand.Seed(time.Now().UnixNano())

	port := getPort()
	user := flag.String("user", "", "username for the proxy basic auth")
	pwd := flag.String("password", "", "password for the proxy basic auth")

	flag.Parse()

	if *user == "" {
		*user = randSeq(10)
	}

	if *pwd == "" {
		*pwd = randSeq(10)
	}

	log.Printf("user: %s", *user)
	log.Printf("password: %s", *pwd)
	log.Printf("port: %d", port)


	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: port,
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
