package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
	},
	Timeout: 30 * time.Second,
}

var (
	activeHTTP    atomic.Int64
	activeTunnels atomic.Int64
	totalHTTP     atomic.Int64
	totalTunnels  atomic.Int64
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	proxy := &http.Server{
		Addr:         ":" + port,
		Handler:      http.HandlerFunc(handle),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Periodic stats
	go func() {
		for range time.Tick(60 * time.Second) {
			log.Printf("STATS  active_http=%d active_tunnels=%d total_http=%d total_tunnels=%d",
				activeHTTP.Load(), activeTunnels.Load(), totalHTTP.Load(), totalTunnels.Load())
		}
	}()

	log.Printf("START  proxy listening on :%s (pid=%d)", port, os.Getpid())
	log.Fatal(proxy.ListenAndServe())
}

func handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("REQ    %s %s from %s proto=%s content_length=%d",
		r.Method, r.RequestURI, r.RemoteAddr, r.Proto, r.ContentLength)

	if r.Method == http.MethodConnect {
		handleTunnel(w, r)
		return
	}
	handleHTTP(w, r)
}

func copyHeaders(dst, src http.Header) {
	toStrip := make(map[string]struct{})
	for _, f := range src["Connection"] {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" {
				toStrip[http.CanonicalHeaderKey(name)] = struct{}{}
			}
		}
	}
	for k, vs := range src {
		if _, hop := hopByHopHeaders[k]; hop {
			continue
		}
		if _, strip := toStrip[k]; strip {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	activeHTTP.Add(1)
	totalHTTP.Add(1)
	defer activeHTTP.Add(-1)

	start := time.Now()
	log.Printf("HTTP   >> %s %s host=%s from=%s", r.Method, r.URL, r.URL.Host, r.RemoteAddr)

	if r.URL.Host == "" {
		log.Printf("HTTP   rejected: missing host from %s", r.RemoteAddr)
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}

	r.RequestURI = ""
	r.Host = r.URL.Host

	log.Printf("HTTP   forwarding %s %s", r.Method, r.URL)
	resp, err := httpClient.Do(r)
	if err != nil {
		log.Printf("HTTP   !! error: %s %s -> %v (%s)", r.Method, r.URL, err, time.Since(start))
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Printf("HTTP   << %s %s status=%d content_length=%d", r.Method, r.URL, resp.StatusCode, resp.ContentLength)

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	buf := bufPool.Get().(*[]byte)
	n, copyErr := io.CopyBuffer(w, resp.Body, *buf)
	bufPool.Put(buf)

	if copyErr != nil {
		log.Printf("HTTP   !! copy error: %s %s -> %v (wrote %d bytes)", r.Method, r.URL, copyErr, n)
	}

	log.Printf("HTTP   done %s %s -> %d (%d bytes, %s)", r.Method, r.URL, resp.StatusCode, n, time.Since(start))
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	activeTunnels.Add(1)
	totalTunnels.Add(1)
	defer activeTunnels.Add(-1)

	start := time.Now()
	log.Printf("TUNNEL >> CONNECT %s from=%s", r.Host, r.RemoteAddr)

	log.Printf("TUNNEL dialing %s", r.Host)
	dest, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		log.Printf("TUNNEL !! dial error: %s -> %v (%s)", r.Host, err, time.Since(start))
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if tc, ok := dest.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	log.Printf("TUNNEL connected %s -> %s", r.Host, dest.RemoteAddr())

	hj, ok := w.(http.Hijacker)
	if !ok {
		dest.Close()
		log.Printf("TUNNEL !! hijack not supported for %s", r.Host)
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	conn, buf, err := hj.Hijack()
	if err != nil {
		dest.Close()
		log.Printf("TUNNEL !! hijack error: %s -> %v", r.Host, err)
		return
	}
	log.Printf("TUNNEL hijacked %s, client=%s", r.Host, conn.RemoteAddr())

	if buf.Reader.Buffered() > 0 {
		buffered := buf.Reader.Buffered()
		data := make([]byte, buffered)
		buf.Read(data)
		dest.Write(data)
		log.Printf("TUNNEL flushed %d buffered bytes to %s", buffered, r.Host)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n := halfPipe(dest, conn)
		log.Printf("TUNNEL client->server %s: %s transferred", r.Host, formatBytes(n))
	}()
	go func() {
		defer wg.Done()
		n := halfPipe(conn, dest)
		log.Printf("TUNNEL server->client %s: %s transferred", r.Host, formatBytes(n))
	}()
	wg.Wait()

	conn.Close()
	dest.Close()
	log.Printf("TUNNEL << closed %s (%s)", r.Host, time.Since(start))
}

func halfPipe(dst, src net.Conn) int64 {
	buf := bufPool.Get().(*[]byte)
	n, _ := io.CopyBuffer(dst, src, *buf)
	bufPool.Put(buf)
	if tc, ok := dst.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	return n
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}


