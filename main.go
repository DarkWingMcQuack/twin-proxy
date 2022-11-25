package main

import (
	"crypto/rsa"
	"crypto/tls"
	"log"
	"encoding/json"
	"net/http"
	cr "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"strconv"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"
	"math/rand"
	"math/big"
	"time"

	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"
	"github.com/phayes/freeport"




)
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

type IP struct {
	Query string
}

func getip() string {
	req, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		return err.Error()
	}
	defer req.Body.Close()

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err.Error()
	}

	var ip IP
	json.Unmarshal(body, &ip)

	return ip.Query
}
type CustomCertsStorage struct {
	// certsCache is a cache with the generated certificates.
	certsCache map[string]*tls.Certificate
}

// Get gets the certificate from the storage.
func (c *CustomCertsStorage) Get(key string) (cert *tls.Certificate, ok bool) {
	cert, ok = c.certsCache[key]

	return cert, ok
}

// Set saves the certificate to the storage.
func (c *CustomCertsStorage) Set(key string, cert *tls.Certificate) {
	c.certsCache[key] = cert
}


func createTLSStuff(ip string) {
	key, err := rsa.GenerateKey(cr.Reader, 2048)
	if err != nil {
		log.Fatal("Private key cannot be created.", err.Error())
	}

	// Generate a pem block with the private key
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if err := os.WriteFile("key.pem", keyPem, 0600); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote key.pem\n")


	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := cr.Int(cr.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SecretCorp"},
		},
		DNSNames:  []string{ip},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate.
	derBytes, err := x509.CreateCertificate(cr.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		log.Fatal("Failed to encode certificate to PEM")
	}
	if err := os.WriteFile("cert.pem", pemCert, 0644); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote cert.pem\n")



}

func loadCert() *tls.Config {
	tlsCert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal("Cannot be loaded the certificate.", err.Error())
	}

	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, &CustomCertsStorage{
		certsCache: map[string]*tls.Certificate{}},
	)

	if err != nil {
		log.Fatal(err)
	}

	// Generate certs valid for 7 days.
	mitmConfig.SetValidity(time.Hour * 24 * 7)
	// Set certs organization.
	mitmConfig.SetOrganization("secret")

	// Generate a cert-key pair for the HTTP-over-TLS proxy.
	proxyCert, err := mitmConfig.GetOrCreateCert("127.0.0.1")
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*proxyCert},
	}
}

func ensureTLSStuff(){
	var should_create bool

	if _, err := os.Stat("cert.pem"); errors.Is(err, os.ErrNotExist) {
		should_create = true
	}

	if _, err := os.Stat("key.pem"); errors.Is(err, os.ErrNotExist) {
		should_create = true
	}

	if should_create {
		ip := getip()
		createTLSStuff(ip)
	}
}

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func getPwd() string {
	var pwd string

	buf, err := ioutil.ReadFile("pwd.txt")

	if err != nil {
		pwd = randSeq(10)
	}else{
		pwd = string(buf)
	}

	f, err := os.Create("pwd.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	f.Write([]byte(pwd))

	return pwd
}

func getUser() string {
	var user string

	buf, err := ioutil.ReadFile("user.txt")

	if err != nil {
		user = randSeq(10)
	}else{
		user = string(buf)
	}

	f, err := os.Create("user.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	f.Write([]byte(user))

	return user
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

	ensureTLSStuff()

	port := getPort()
	user := getUser()
	pwd := getPwd()

	log.Printf("user: %s", user)
	log.Printf("password: %s", pwd)
	log.Printf("port: %d", port)


	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: port,
		},
		OnRequest:  onRequest,
		OnResponse: onResponse,
		Username: user,
		Password: pwd,
		TLSConfig:  loadCert(),

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
