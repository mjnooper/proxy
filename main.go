package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var hopHeaders = map[string]struct{}{
	"Connection": {}, "Keep-Alive": {}, "Proxy-Authenticate": {},
	"Proxy-Authorization": {}, "Te": {}, "Trailer": {},
	"Transfer-Encoding": {}, "Upgrade": {},
}

var pool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

var client = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
	},
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	s := &http.Server{
		Addr:         ":" + port,
		Handler:      http.HandlerFunc(handle),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	s.ListenAndServe()
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		tunnel(w, r)
	} else {
		forward(w, r)
	}
}

func forward(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}
	r.RequestURI = ""
	r.Host = r.URL.Host

	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	strip := map[string]struct{}{}
	for _, f := range resp.Header["Connection"] {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" {
				strip[http.CanonicalHeaderKey(name)] = struct{}{}
			}
		}
	}
	for k, vs := range resp.Header {
		if _, ok := hopHeaders[k]; ok {
			continue
		}
		if _, ok := strip[k]; ok {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	buf := pool.Get().(*[]byte)
	io.CopyBuffer(w, resp.Body, *buf)
	pool.Put(buf)
}

func tunnel(w http.ResponseWriter, r *http.Request) {
	dest, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if tc, ok := dest.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		dest.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	conn, buf, err := hj.Hijack()
	if err != nil {
		dest.Close()
		return
	}

	if buf.Reader.Buffered() > 0 {
		data := make([]byte, buf.Reader.Buffered())
		buf.Read(data)
		dest.Write(data)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipe(dest, conn) }()
	go func() { defer wg.Done(); pipe(conn, dest) }()
	wg.Wait()
	conn.Close()
	dest.Close()
}

func pipe(dst, src net.Conn) {
	buf := pool.Get().(*[]byte)
	io.CopyBuffer(dst, src, *buf)
	pool.Put(buf)
	if tc, ok := dst.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}
