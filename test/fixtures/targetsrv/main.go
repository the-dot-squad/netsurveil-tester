// Command targetsrv is the upstream every e2e scenario talks to. It behaves
// like a healthy site on all ports; the censor sidecar in front of the node
// is what makes some of them look blocked or throttled.
//
//	8080  HTTP: /, /status/451, /redirect-sinkhole, /blob?bytes=N, /forbidden-keyword,
//	      /article (64 KiB page quoting a block phrase)
//	8081  HTTP, throttled by the censor
//	8082  HTTP, always answers with a block page
//	8083  HTTP, stalled by the censor after 64 KiB
//	8443  HTTPS + QUIC (UDP dropped by the censor), advertises h3
//	8444  HTTPS + QUIC, advertises h3
//	9443  HTTPS for any SNI (the censor resets blocked-sni.test)
//	7000-7003 TCP accept
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const maxBlob = 10 << 20

func main() {
	cert := selfSigned()
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	for _, p := range []string{":8080", ":8081", ":8083"} {
		go serveHTTP(p, site(""), nil)
	}
	go serveHTTP(":8082", blockPage(), nil)
	go serveHTTP(":9443", site(""), tlsCfg)
	for _, p := range []string{":8443", ":8444"} {
		go serveHTTP(p, site(`h3="`+p+`"; ma=86400`), tlsCfg)
		go serveQUIC(p, tlsCfg)
	}
	for port := 7000; port <= 7003; port++ {
		go serveTCP(":" + strconv.Itoa(port))
	}
	log.Println("targetsrv ready")
	select {}
}

func site(altSvc string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		if altSvc != "" {
			w.Header().Set("Alt-Svc", altSvc)
		}
		_, _ = io.WriteString(w, "<html><head><title>Allowed</title></head><body>hello</body></html>")
	})
	mux.HandleFunc("/status/451", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnavailableForLegalReasons)
	})
	mux.HandleFunc("/redirect-sinkhole", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.10.34.34/", http.StatusFound)
	})
	mux.HandleFunc("/forbidden-keyword", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reachable only without a keyword filter")
	})
	mux.HandleFunc("/article", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html><head><title>How censors work</title></head><body><p>A typical notice reads: "+
			"access to this website has been blocked by order of the regulator.</p>"+strings.Repeat("<p>Ordinary article text.</p>", 2400)+"</body></html>")
	})
	mux.HandleFunc("/blob", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
		if err != nil || n < 0 || n > maxBlob {
			http.Error(w, "bytes must be 0-10485760", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		chunk := make([]byte, 32<<10)
		for n > 0 {
			k, err := w.Write(chunk[:min(n, len(chunk))])
			if err != nil {
				return
			}
			n -= k
		}
	})
	return mux
}

func blockPage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html><head><title>Blocked</title></head><body>Access to this website has been blocked by order of the regulator.</body></html>")
	})
}

func serveHTTP(addr string, h http.Handler, tlsCfg *tls.Config) {
	srv := &http.Server{Addr: addr, Handler: h, TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}
	var err error
	if tlsCfg != nil {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	log.Fatalf("%s: %v", addr, err)
}

func serveQUIC(addr string, base *tls.Config) {
	cfg := base.Clone()
	cfg.NextProtos = []string{"h3"}
	ln, err := quic.ListenAddr(addr, cfg, nil)
	if err != nil {
		log.Fatalf("quic %s: %v", addr, err)
	}
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Fatalf("quic %s: %v", addr, err)
		}
		go func() {
			time.Sleep(2 * time.Second)
			_ = conn.CloseWithError(0, "")
		}()
	}
}

func serveTCP(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("%s: %v", addr, err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatalf("%s: %v", addr, err)
		}
		_ = c.Close()
	}
}

func selfSigned() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "allowed.test"},
		DNSNames:     []string{"allowed.test", "blocked-sni.test", "*.test"},
		IPAddresses:  []net.IP{net.ParseIP("172.30.0.20")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(fmt.Errorf("certificate: %w", err))
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
