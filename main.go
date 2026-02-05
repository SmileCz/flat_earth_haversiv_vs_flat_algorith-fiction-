package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// asyncWriter writes access logs to stdout and optionally to a file asynchronously
	logWriter *asyncLogWriter
	// config
	accessLogFile             = getEnv("ACCESS_LOG_FILE", "/logs/access.log")
	anonIP                    = getEnv("ANONYMIZE_IP", "true") == "true"
	ipHashSecret              = getEnv("IP_HASH_SECRET", "")
	accessLogBufferSizeStr    = getEnv("ACCESS_LOG_BUFFER_SIZE", "1000")
	logRotateBytesStr         = getEnv("LOG_ROTATE_BYTES", "10485760") // 10MB
	logRotateMaxFilesStr      = getEnv("LOG_ROTATE_MAX_FILES", "7")    // keep 7 files
	logRotateCheckIntervalStr = getEnv("LOG_ROTATE_CHECK_INTERVAL", "60")
	logRotateMinIntervalStr   = getEnv("LOG_ROTATE_MIN_INTERVAL_SECONDS", "5") // minimum seconds between rotations
	// log sink (none|loki)
	logSink       = getEnv("LOG_SINK", "")
	lokiURL       = getEnv("LOKI_URL", "")
	lokiLabelsStr = getEnv("LOKI_LABELS", "{\"job\":\"plochy\"}")
)

// asyncLogWriter buffers log lines and writes them in background to configured writers
type asyncLogWriter struct {
	writers []Writer
	ch      chan []byte
	dropped uint64
	client  *http.Client
	lokiCfg lokiConfig
}

type lokiConfig struct {
	enabled bool
	url     string
	labels  map[string]string
}

func newAsyncLogWriter(writers []Writer, buf int) *asyncLogWriter {
	alw := &asyncLogWriter{writers: writers, ch: make(chan []byte, buf)}
	// setup http client and loki config
	alw.client = &http.Client{Timeout: 5 * time.Second}
	alw.lokiCfg = parseLokiConfig()
	go alw.loop()
	return alw
}

func parseLokiConfig() lokiConfig {
	cfg := lokiConfig{}
	if strings.ToLower(strings.TrimSpace(logSink)) == "loki" && lokiURL != "" {
		cfg.enabled = true
		cfg.url = lokiURL
		// parse labels JSON
		m := map[string]string{}
		_ = json.Unmarshal([]byte(lokiLabelsStr), &m)
		if len(m) == 0 {
			m = map[string]string{"job": "plochy"}
		}
		cfg.labels = m
	}
	return cfg
}

func (a *asyncLogWriter) loop() {
	for b := range a.ch {
		for _, w := range a.writers {
			_, err := w.Write(b)
			if err != nil {
				// best-effort: write error to stderr
				log.Printf("error writing access log: %v", err)
			}
		}
		// optionally send to loki
		if a.lokiCfg.enabled {
			_ = a.sendToLoki(b)
		}
	}
}

func (a *asyncLogWriter) sendToLoki(b []byte) error {
	// prepare payload: {streams: [{stream: labels, values: [["<unix_nano>", "<line>"]] }]}
	line := strings.TrimSpace(string(b))
	now := fmt.Sprintf("%d", time.Now().UnixNano())
	payload := map[string]interface{}{
		"streams": []map[string]interface{}{
			{
				"stream": a.lokiCfg.labels,
				"values": [][]string{{now, line}},
			},
		},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", a.lokiCfg.url, bytes.NewBuffer(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("loki push failed: status=%d", resp.StatusCode)
	}
	return nil
}

func (a *asyncLogWriter) Write(p []byte) (n int, err error) {
	// copy p because caller may reuse buffer
	d := make([]byte, len(p))
	copy(d, p)
	select {
	case a.ch <- d:
		return len(p), nil
	default:
		// channel full - count dropped and fallback to direct stdout write to avoid total loss
		atomic.AddUint64(&a.dropped, 1)
		_, err := os.Stdout.Write(p)
		return len(p), err
	}
}

// Close the writer (drain channel)
func (a *asyncLogWriter) Close() {
	close(a.ch)
}

// Writer minimal interface we need (os.File and stdout implement)
type Writer interface {
	Write(p []byte) (n int, err error)
}

// fileRotator implements Writer and rotates file when exceeds maxBytes
type fileRotator struct {
	path       string
	mu         sync.Mutex
	file       *os.File
	maxBytes   int64
	maxFiles   int
	checkEvery time.Duration
	// minInterval prevents rotating more often than this duration
	minInterval time.Duration
	// lastRotate stores time of last rotation
	lastRotate time.Time
}

func newFileRotator(path string, maxBytes int64, maxFiles int, minInterval, checkEvery time.Duration) (*fileRotator, error) {
	r := &fileRotator{path: path, maxBytes: maxBytes, maxFiles: maxFiles, checkEvery: checkEvery, minInterval: minInterval}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	r.file = f

	// try to read persisted lastRotate timestamp (unix seconds) from file
	lastFile := path + ".last_rotate"
	if b, err := os.ReadFile(lastFile); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
				r.lastRotate = time.Unix(sec, 0)
			}
		}
	}

	// background ticker to enforce rotation periodically
	if checkEvery > 0 {
		go func() {
			t := time.NewTicker(checkEvery)
			defer t.Stop()
			for range t.C {
				r.mu.Lock()
				_ = r.maybeRotateLocked()
				r.mu.Unlock()
			}
		}()
	}
	return r, nil
}

func (r *fileRotator) Write(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// if write would exceed maxBytes, rotate first
	if r.maxBytes > 0 {
		st, err := r.file.Stat()
		if err == nil && st.Size()+int64(len(p)) > r.maxBytes {
			if err := r.maybeRotateLocked(); err != nil {
				// continue and try to write
				log.Printf("log rotate error: %v", err)
			}
		}
	}
	n, err = r.file.Write(p)
	return n, err
}

// maybeRotateLocked assumes r.mu is held
func (r *fileRotator) maybeRotateLocked() error {
	if r.file == nil {
		return nil
	}
	// enforce minimum interval between rotations
	if !r.lastRotate.IsZero() && r.minInterval > 0 {
		if time.Since(r.lastRotate) < r.minInterval {
			// skip rotation to avoid rapid successive rotations
			return nil
		}
	}
	st, err := r.file.Stat()
	if err != nil {
		return err
	}
	if r.maxBytes > 0 && st.Size() <= r.maxBytes {
		return nil
	}
	// close current file
	if err := r.file.Close(); err != nil {
		return err
	}
	// rename with timestamp
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	rotated := fmt.Sprintf("%s.%s", r.path, timestamp)
	if err := os.Rename(r.path, rotated); err != nil {
		// if rename fails, try to reopen file and continue
		f, ferr := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if ferr == nil {
			r.file = f
			return nil
		}
		return err
	}
	// reopen new log file
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	r.file = f
	// update lastRotate timestamp
	r.lastRotate = time.Now()
	// persist lastRotate to file atomically
	_ = persistLastRotateAtomic(r.path, r.lastRotate)
	// cleanup old rotated files
	_ = r.cleanupLocked()
	return nil
}

func persistLastRotateAtomic(path string, t time.Time) error {
	lastFile := path + ".last_rotate"
	tmp := lastFile + ".tmp"
	data := []byte(strconv.FormatInt(t.Unix(), 10))
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, lastFile)
}

func (r *fileRotator) cleanupLocked() error {
	// list rotated files with prefix path + "."
	dir := filepath.Dir(r.path)
	base := filepath.Base(r.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var rotated []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, base+".") {
			rotated = append(rotated, filepath.Join(dir, name))
		}
	}
	if len(rotated) <= r.maxFiles {
		return nil
	}
	// sort by name (timestamp suffix) ascending
	sort.Strings(rotated)
	// remove oldest
	toRemove := len(rotated) - r.maxFiles
	for i := 0; i < toRemove; i++ {
		_ = os.Remove(rotated[i])
	}
	return nil
}

func init() {
	// determine buffer size
	buf := 1000
	if v := parseInt(accessLogBufferSizeStr, 1000); v > 0 {
		buf = v
	}
	// determine rotation params
	maxBytes := int64(parseInt(logRotateBytesStr, 10485760))
	maxFiles := parseInt(logRotateMaxFilesStr, 7)
	checkSec := parseInt(logRotateCheckIntervalStr, 60)
	checkEvery := time.Duration(checkSec) * time.Second
	// minimum interval between rotations
	minIntervalSec := parseInt(logRotateMinIntervalStr, 5)
	minInterval := time.Duration(minIntervalSec) * time.Second

	writers := []Writer{os.Stdout}
	if accessLogFile != "" {
		// ensure directory exists
		dir := "/logs"
		if idx := strings.LastIndex(accessLogFile, "/"); idx > 0 {
			dir = accessLogFile[:idx]
		}
		_ = os.MkdirAll(dir, 0755)
		// use file rotator
		r, err := newFileRotator(accessLogFile, maxBytes, maxFiles, minInterval, checkEvery)
		if err == nil {
			writers = append(writers, r)
		} else {
			log.Printf("warning: could not create log rotator %s: %v", accessLogFile, err)
		}
	}
	logWriter = newAsyncLogWriter(writers, buf)

	// if ipHashSecret empty, try Docker secrets files
	if ipHashSecret == "" {
		// common secret file paths
		candidates := []string{"/run/secrets/ip_hash_secret", "/run/secrets/IP_HASH_SECRET"}
		for _, p := range candidates {
			if b, err := os.ReadFile(p); err == nil {
				ipHashSecret = strings.TrimSpace(string(b))
				break
			}
		}
		if ipHashSecret == "" {
			if anonIP {
				log.Printf("INFO: IP hashing secret not set (IP_HASH_SECRET). Falling back to masking IPv4/IPv6.")
			}
		}
	}
}

func main() {
	mux := http.NewServeMux()
	// Serve static files from /static (we'll copy project files there in the image)
	fs := http.FileServer(http.Dir("/static"))
	// Wrap the file server with logging middleware
	mux.Handle("/", loggingMiddleware(fs))

	srv := &http.Server{
		Addr:         ":80",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Println("Starting static server on :80")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// loggingResponseWriter wraps http.ResponseWriter to capture status and bytes written
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *loggingResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// getClientIP extracts client IP from headers or RemoteAddr
func getClientIP(r *http.Request) string {
	// Common headers used by proxies / CDNs
	headers := []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"}
	for _, h := range headers {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			// X-Forwarded-For may contain comma separated list
			parts := strings.Split(v, ",")
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	// Fallback to RemoteAddr
	if addr := r.RemoteAddr; addr != "" {
		ip, _, err := net.SplitHostPort(addr)
		if err == nil {
			return ip
		}
		return addr
	}
	return "unknown"
}

// parseInt helper
func parseInt(s string, def int) int {
	if s == "" {
		return def
	}
	var v int
	_, err := fmt.Sscanf(s, "%d", &v)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// maskIP anonymizes an IP string by masking last octet (IPv4) or last 4 hextets (IPv6)
func maskIP(ip string) string {
	if ip == "" || ip == "unknown" {
		return ip
	}
	// Try parse
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// if it contains port try to split
		if h, _, err := net.SplitHostPort(ip); err == nil {
			parsed = net.ParseIP(h)
		}
		if parsed == nil {
			// fallback: mask last char
			if idx := strings.LastIndex(ip, "."); idx != -1 {
				return ip[:idx+1] + "0"
			}
			return ip
		}
	}
	if parsed.To4() != nil {
		// IPv4: zero last octet
		parts := strings.Split(parsed.String(), ".")
		if len(parts) == 4 {
			parts[3] = "0"
			return strings.Join(parts, ".")
		}
		return parsed.String()
	}
	// IPv6: mask last 4 hextets
	hextets := strings.Split(parsed.String(), ":")
	if len(hextets) > 4 {
		for i := len(hextets) - 4; i < len(hextets); i++ {
			hextets[i] = "0000"
		}
		return strings.Join(hextets, ":")
	}
	return parsed.String()
}

// hashIP returns HMAC-SHA256 hex of the IP using ipHashSecret. If secret empty, fallback to maskIP.
func hashIP(ip string) string {
	if ip == "" || ip == "unknown" {
		return ip
	}
	if ipHashSecret == "" {
		return maskIP(ip)
	}
	h := hmac.New(sha256.New, []byte(ipHashSecret))
	h.Write([]byte(ip))
	return hex.EncodeToString(h.Sum(nil))
}

// getEnv helper
func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// logEntry represents the structured log fields
type logEntry struct {
	Time                time.Time `json:"time"`
	Method              string    `json:"method"`
	Path                string    `json:"path"`
	Host                string    `json:"host"`
	ClientIP            string    `json:"client_ip"`
	ClientIPMasked      string    `json:"client_ip_masked,omitempty"`
	XForwardedFor       string    `json:"x_forwarded_for,omitempty"`
	XForwardedForMasked string    `json:"x_forwarded_for_masked,omitempty"`
	XRealIP             string    `json:"x_real_ip,omitempty"`
	XRealIPMasked       string    `json:"x_real_ip_masked,omitempty"`
	UserAgent           string    `json:"user_agent,omitempty"`
	Referer             string    `json:"referer,omitempty"`
	AcceptLanguage      string    `json:"accept_language,omitempty"`
	Status              int       `json:"status"`
	Bytes               int       `json:"bytes"`
	DurationMs          int64     `json:"duration_ms"`
	TLS                 bool      `json:"tls"`
	HeadersCount        int       `json:"headers_count"`
}

// loggingMiddleware logs requests and responses (JSON to stdout and file). It logs when a GET results in 2xx.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lrw, r)
		// Only log GET requests that resulted in successful status (2xx) — adjust as needed
		if strings.ToUpper(r.Method) == "GET" && lrw.status >= 200 && lrw.status < 300 {
			clientIP := getClientIP(r)
			var masked string
			xff := r.Header.Get("X-Forwarded-For")
			xffMasked := xff
			xreal := r.Header.Get("X-Real-IP")
			xrealMasked := xreal
			if anonIP {
				masked = hashIP(clientIP)
				if xff != "" {
					parts := strings.Split(xff, ",")
					parts[0] = hashIP(strings.TrimSpace(parts[0]))
					xffMasked = strings.Join(parts, ",")
				}
				if xreal != "" {
					xrealMasked = hashIP(xreal)
				}
			} else {
				masked = maskIP(clientIP)
				if xff != "" {
					parts := strings.Split(xff, ",")
					parts[0] = maskIP(strings.TrimSpace(parts[0]))
					xffMasked = strings.Join(parts, ",")
				}
				if xreal != "" {
					xrealMasked = maskIP(xreal)
				}
			}

			entry := logEntry{
				Time:                start.UTC(),
				Method:              r.Method,
				Path:                r.URL.Path,
				Host:                r.Host,
				ClientIP:            clientIP,
				ClientIPMasked:      masked,
				XForwardedFor:       xff,
				XForwardedForMasked: xffMasked,
				XRealIP:             xreal,
				XRealIPMasked:       xrealMasked,
				UserAgent:           r.UserAgent(),
				Referer:             r.Referer(),
				AcceptLanguage:      r.Header.Get("Accept-Language"),
				Status:              lrw.status,
				Bytes:               lrw.bytes,
				DurationMs:          time.Since(start).Milliseconds(),
				TLS:                 r.TLS != nil,
				HeadersCount:        len(r.Header),
			}
			b, err := json.Marshal(entry)
			if err != nil {
				// Fallback to plain log
				log.Printf("[access] %s %s %s status=%d bytes=%d duration=%dms (marshal error: %v)", entry.Method, entry.Path, entry.ClientIP, entry.Status, entry.Bytes, entry.DurationMs, err)
				return
			}
			// Write JSON log to configured writers
			logWriter.Write(append(b, '\n'))
		}
	})
}
