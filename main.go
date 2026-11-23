package main

// ============================================================
// endpoint-hunter2 — main.go
//
// Build (dir terpisah, package: *.go + go.mod):
//   go build -o endpoint-hunter2 .
//
//   * --httpx-json <file|-> : body-reuse dari `httpx -json -irr` (streaming,
//     baris raksasa tidak menghentikan pembacaan; body dipotong 10MB).
//   * Fetch mode: header -H / -ua dikirim di SEMUA request (termasuk redirect),
//     Cookie dari beberapa -H digabung, -H "Host: x" diterapkan ke req.Host.
//   * Hasil digabung deterministik (urutan input), endpoint relatif dari JS di
//     CDN ditempel ke origin halaman yang memuat JS (<script src>).
//   * Exit code: 0 sukses, 1 error input/output, 130 diinterupsi.
// ============================================================

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	version   = "2.1.0"
	defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	maxBodyMB = 10
	// batas satu baris JSONL httpx (-irr memuat body + raw response, ter-escape;
	// body 10MB bisa jadi >60MB). Baris di atas ini dilewati (dihitung), bukan
	// menghentikan seluruh pembacaan seperti bufio.Scanner dulu.
	maxJSONLLine = 256 << 20
	banner       = `
  _____           _             _       _   _   _             _
 | ____|_ __   __| |_ __   ___ (_)_ __ | |_| | | |_   _ _ __ | |_ ___ _ __
 |  _| | '_ \ / _` + "`" + ` | '_ \ / _ \| | '_ \| __| |_| | | | | '_ \| __/ _ \ '__|
 | |___| | | | (_| | |_) | (_) | | | | | |_|  _  | |_| | | | | ||  __/ |
 |_____|_| |_|\__,_| .__/ \___/|_|_| |_|\__|_| |_|\__,_|_| |_|\__\___|_|
                    |_|

  JS Endpoint Discovery Tool for Bug Bounty  v%s
  Extract hidden API endpoints missed by standard recon
`
)

// ─── ANSI Colors ──────────────────────────────────────────────────────────────

const (
	cReset   = "\033[0m"
	cRed     = "\033[31m"
	cGreen   = "\033[32m"
	cYellow  = "\033[33m"
	cBlue    = "\033[34m"
	cMagenta = "\033[35m"
	cCyan    = "\033[36m"
	cBold    = "\033[1m"
	cDim     = "\033[2m"
	cWhite   = "\033[97m"
)

// ─── Config ───────────────────────────────────────────────────────────────────

type Config struct {
	URLs            []string
	ListFile        string
	KnownFile       string
	LocalJS         string
	BaseURL         string
	Scope           string
	ScopeExact      exactScopeValue // --scope-exact: bare=modifier, =Ddomain=tepat D
	BaseScope       bool            // -bs/--base-scope: scope otomatis dari registrable domain input
	HTTPXJSON       string          // JSONL dari httpx -json -irr
	Threads         int
	DelayMs         int
	RatePerSec      float64
	UserAgent       string
	UAExplicit      bool // -ua diberikan eksplisit -> menang atas UA FlareSolverr
	FlareSolvrURL   string
	OutputFile      string
	OutPrefix       string
	OutputJSON      bool
	Timeout         int
	Silent          bool
	Verbose         bool
	NoColor         bool
	NoSource        bool
	URLsOnly        bool
	Fuzz            bool
	Curl            bool
	BodyFormat      string
	IncludeAssets   bool
	IncludeExternal bool
	ExtraHeaders    []string
	MaxBodyBytes    int64

	headers   []hdrKV // -H ter-parse (tanpa Cookie/Host)
	hdrCookie string  // gabungan semua -H Cookie
	hdrHost   string  // -H Host
	hdrUA     string  // -H User-Agent (menang atas -ua)
}

type hdrKV struct{ name, value string }

// parseHeaders: validasi -H "Name: value". Cookie dari beberapa -H digabung
// (dulu Header.Set -> -H Cookie terakhir menimpa cookie identitas/FlareSolverr).
func parseHeaders(cfg *Config) []string {
	var bad []string
	var cookies []string
	for _, h := range cfg.ExtraHeaders {
		parts := strings.SplitN(h, ":", 2)
		name := strings.TrimSpace(parts[0])
		if len(parts) != 2 || name == "" || strings.ContainsAny(name, " \t\r\n") {
			bad = append(bad, h)
			continue
		}
		val := strings.TrimSpace(parts[1])
		switch strings.ToLower(name) {
		case "cookie":
			if val != "" {
				cookies = append(cookies, val)
			}
		case "host":
			cfg.hdrHost = val
		case "user-agent":
			cfg.hdrUA = val
		default:
			cfg.headers = append(cfg.headers, hdrKV{name, val})
		}
	}
	cfg.hdrCookie = strings.Join(cookies, "; ")
	return bad
}

// ─── FlareSolverr ─────────────────────────────────────────────────────────────

type fsRequest struct {
	Cmd        string `json:"cmd"`
	URL        string `json:"url"`
	MaxTimeout int    `json:"maxTimeout"`
}

type fsResponse struct {
	Status   string     `json:"status"`
	Solution fsSolution `json:"solution"`
	Message  string     `json:"message"`
}

type fsSolution struct {
	UserAgent string     `json:"userAgent"`
	Cookies   []fsCookie `json:"cookies"`
	Response  string     `json:"response"`
}

type fsCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type FSSession struct {
	Cookies   string
	UserAgent string
}

type FSCache struct {
	mu       sync.RWMutex
	sessions map[string]*FSSession
	solving  map[string]*sync.Once
}

func newFSCache() *FSCache {
	return &FSCache{
		sessions: make(map[string]*FSSession),
		solving:  make(map[string]*sync.Once),
	}
}

func (fc *FSCache) Resolve(cfg *Config, scheme, domain string) *FSSession {
	fc.mu.RLock()
	if s, ok := fc.sessions[domain]; ok {
		fc.mu.RUnlock()
		return s
	}
	fc.mu.RUnlock()

	fc.mu.Lock()
	if _, ok := fc.solving[domain]; !ok {
		fc.solving[domain] = &sync.Once{}
	}
	once := fc.solving[domain]
	fc.mu.Unlock()

	once.Do(func() {
		sess := solveDomain(cfg, scheme, domain)
		fc.mu.Lock()
		fc.sessions[domain] = sess
		fc.mu.Unlock()
	})

	fc.mu.RLock()
	s := fc.sessions[domain]
	fc.mu.RUnlock()
	return s
}

// Invalidate menghapus sesi domain agar Resolve berikutnya solve ulang.
func (fc *FSCache) Invalidate(domain string) {
	fc.mu.Lock()
	delete(fc.sessions, domain)
	delete(fc.solving, domain)
	fc.mu.Unlock()
}

// fsClient: client khusus FlareSolverr dengan timeout lebih panjang (solve bisa
// 40-60s), tidak bergantung pada --timeout.
var fsClient = &http.Client{
	Timeout: 90 * time.Second,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	},
}

func solveDomain(cfg *Config, scheme, domain string) *FSSession {
	if scheme != "http" {
		scheme = "https"
	}
	body, _ := json.Marshal(fsRequest{Cmd: "request.get", URL: scheme + "://" + domain, MaxTimeout: 60000})
	resp, err := fsClient.Post(strings.TrimRight(cfg.FlareSolvrURL, "/")+"/v1", "application/json", bytes.NewReader(body))
	if err != nil {
		logVerbose(cfg, "FlareSolverr %s: %v", domain, err)
		return nil
	}
	defer resp.Body.Close()
	var fsResp fsResponse
	if err := json.NewDecoder(resp.Body).Decode(&fsResp); err != nil || fsResp.Status != "ok" {
		logVerbose(cfg, "FlareSolverr %s: status=%q err=%v", domain, fsResp.Status, err)
		return nil
	}
	var cookieParts []string
	for _, c := range fsResp.Solution.Cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	return &FSSession{Cookies: strings.Join(cookieParts, "; "), UserAgent: fsResp.Solution.UserAgent}
}

// ─── HTTP Fetcher ─────────────────────────────────────────────────────────────

var fsCache = newFSCache()
var httpClient *http.Client // shared (keep-alive)

func buildClient(cfg *Config) *http.Client {
	perHost := cfg.Threads + 10
	if perHost > 256 {
		perHost = 256
	}
	return &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		// Go meneruskan header request awal (UA, -H identitas) ke setiap hop
		// redirect; Cookie/Authorization dibuang bila pindah domain (aman).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          512,
			MaxIdleConnsPerHost:   perHost,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: time.Duration(cfg.Timeout) * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

// buildRequest: request GET dgn header identitas lengkap.
func buildRequest(cfg *Config, rawURL string, sess *FSSession) (*http.Request, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	ua := cfg.UserAgent
	if sess != nil && sess.UserAgent != "" && !cfg.UAExplicit {
		ua = sess.UserAgent // cf_clearance terikat UA solver
	}
	if cfg.hdrUA != "" {
		ua = cfg.hdrUA
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	var cookies []string
	if sess != nil && sess.Cookies != "" {
		cookies = append(cookies, sess.Cookies)
	}
	if cfg.hdrCookie != "" {
		cookies = append(cookies, cfg.hdrCookie)
	}
	if len(cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(cookies, "; "))
	}
	for _, h := range cfg.headers {
		req.Header.Set(h.name, h.value)
	}
	if cfg.hdrHost != "" {
		req.Host = cfg.hdrHost
	}
	return req, nil
}

type fetched struct {
	body, finalURL, contentType string
}

func fetchContent(cfg *Config, rawURL string) (fetched, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fetched{}, fmt.Errorf("invalid URL")
	}
	for attempt := 0; attempt < 2; attempt++ {
		var sess *FSSession
		if cfg.FlareSolvrURL != "" {
			sess = fsCache.Resolve(cfg, u.Scheme, u.Host)
		}
		req, err := buildRequest(cfg, rawURL, sess)
		if err != nil {
			return fetched{}, err
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return fetched{}, err
		}
		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			resp.Body.Close()
			if cfg.FlareSolvrURL != "" && attempt == 0 {
				fsCache.Invalidate(u.Host)
				continue
			}
			return fetched{}, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			resp.Body.Close()
			return fetched{}, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxBodyBytes))
		resp.Body.Close()
		if err != nil {
			return fetched{}, err
		}
		f := fetched{body: string(data), finalURL: rawURL, contentType: resp.Header.Get("Content-Type")}
		if resp.Request != nil && resp.Request.URL != nil {
			f.finalURL = resp.Request.URL.String()
		}
		return f, nil
	}
	return fetched{}, fmt.Errorf("blocked after retry")
}

// ─── Output ───────────────────────────────────────────────────────────────────

func colorInterest(cfg *Config, interest string) string {
	if cfg.NoColor {
		return interest
	}
	switch interest {
	case "HIGH":
		return cRed + cBold + "HIGH" + cReset
	case "MED":
		return cYellow + "MED " + cReset
	default:
		return cDim + "LOW " + cReset
	}
}

func colorMethod(cfg *Config, method string) string {
	m := fmt.Sprintf("%-7s", method)
	if cfg.NoColor {
		return m
	}
	switch method {
	case "GET":
		return cGreen + m + cReset
	case "POST":
		return cYellow + m + cReset
	case "PUT", "PATCH":
		return cCyan + m + cReset
	case "DELETE":
		return cRed + m + cReset
	default:
		return cDim + m + cReset
	}
}

func printEndpoint(cfg *Config, ep Endpoint) string {
	params := ""
	if len(ep.Params) > 0 {
		params = fmt.Sprintf("  params=[%s]", strings.Join(ep.Params, ","))
	}
	epURL := ep.AbsURL
	if !cfg.NoColor {
		epURL = cWhite + epURL + cReset
	}
	src := ""
	if !cfg.NoSource {
		if cfg.NoColor {
			src = fmt.Sprintf("  ← %s", ep.Source)
		} else {
			src = fmt.Sprintf("  %s← %s%s", cDim, ep.Source, cReset)
		}
	}
	return fmt.Sprintf("[%s] %s %s%s%s", colorInterest(cfg, ep.Interest), colorMethod(cfg, ep.Method), epURL, params, src)
}

// ─── Known URL Filter ─────────────────────────────────────────────────────────

type KnownSet struct {
	paths map[string]bool
	full  map[string]bool
}

func newKnownSet() *KnownSet {
	return &KnownSet{paths: make(map[string]bool), full: make(map[string]bool)}
}

func (ks *KnownSet) Add(rawURL string) {
	rawURL = strings.TrimSpace(rawURL)
	if f := strings.Fields(rawURL); len(f) > 0 {
		rawURL = f[0] // "url [200] [title]" -> url
	}
	if rawURL == "" || strings.HasPrefix(rawURL, "#") {
		return
	}
	ks.full[dedupKey(rawURL)] = true
	ks.paths[normaliseForFilter(rawURL)] = true
}

// Contains: cocok penuh, atau host(+port non-default)+path sama (skema,
// query, trailing slash, port default diabaikan — normalisasi yang sama
// dipakai saat Add).
func (ks *KnownSet) Contains(rawURL string) bool {
	if ks.full[dedupKey(rawURL)] {
		return true
	}
	return ks.paths[normaliseForFilter(rawURL)]
}

func (ks *KnownSet) Size() int { return len(ks.full) }

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

type RateLimiter struct{ ticker *time.Ticker }

func newRateLimiter(rps float64) *RateLimiter {
	if rps <= 0 {
		return nil
	}
	return &RateLimiter{ticker: time.NewTicker(time.Duration(float64(time.Second) / rps))}
}

func (r *RateLimiter) Wait() {
	if r != nil {
		<-r.ticker.C
	}
}

func (r *RateLimiter) Stop() {
	if r != nil {
		r.ticker.Stop()
	}
}

// ─── Logging ──────────────────────────────────────────────────────────────────

func logVerbose(cfg *Config, format string, args ...interface{}) {
	if cfg.Verbose && !cfg.Silent {
		fmt.Fprintf(os.Stderr, cDim+"[v] "+cReset+format+"\n", args...)
	}
}

func logInfo(cfg *Config, format string, args ...interface{}) {
	if !cfg.Silent {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func logWarn(cfg *Config, format string, args ...interface{}) {
	if !cfg.Silent {
		fmt.Fprintf(os.Stderr, cYellow+"[!]"+cReset+" "+format+"\n", args...)
	}
}

// logErr: error yang memengaruhi hasil — tetap tampil walau -silent.
func logErr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[endpoint-hunter2] "+format+"\n", args...)
}

// ─── Result ───────────────────────────────────────────────────────────────────

type Result struct {
	URL      string   `json:"url"`
	Method   string   `json:"method"`
	Params   []string `json:"params,omitempty"`
	Body     []string `json:"body_params,omitempty"`
	Interest string   `json:"interest"`
	Source   string   `json:"source"`
	// Terstruktur (opsional): "source" = "<url>:<line>:<col>" ambigu bila URL
	// sumber berport (http://127.0.0.1:8011:24:12). String "source" tetap.
	SourceURL string `json:"source_url,omitempty"`
	Line      int    `json:"line,omitempty"`
	Col       int    `json:"col,omitempty"`
}

// toResult: record output (--json / <p>.jsonl) untuk satu endpoint.
func toResult(ep Endpoint, u string, body []string) Result {
	return Result{URL: u, Method: ep.Method, Params: ep.Params, Body: body, Interest: ep.Interest,
		Source: ep.Source, SourceURL: ep.SourceURL, Line: ep.Line, Col: ep.Col}
}

// ─── Worker ───────────────────────────────────────────────────────────────────

type WorkItem struct {
	URL         string
	PageURL     string // final_url httpx (bila ada) — dasar resolusi
	IsLocal     bool
	Content     string
	ContentType string
	seq         int
}

// httpxRecord: baris JSONL httpx -json -irr (field lain diabaikan).
type httpxRecord struct {
	URL         string `json:"url"`
	FinalURL    string `json:"final_url"`
	StatusCode  int    `json:"status_code"`
	Body        string `json:"body"`
	ContentType string `json:"content_type"`
}

// recResult: hasil satu record. eps sudah lolos filter; pending = relatif-origin
// dari JS (filter ditunda sampai atribusi ulang CDN -> origin halaman).
type recResult struct {
	seq       int
	eps       []Endpoint
	pending   []Endpoint
	refs      []string
	docOrigin string
	skipped   int
}

var binaryCTPrefixes = []string{"image/", "audio/", "video/", "font/", "application/octet-stream",
	"application/pdf", "application/zip", "application/x-protobuf", "application/wasm", "application/x-font"}

func isBinaryContent(ct, body string) bool {
	ct = strings.ToLower(ct)
	for _, p := range binaryCTPrefixes {
		if strings.HasPrefix(ct, p) {
			return !strings.HasPrefix(ct, "image/svg") // SVG = teks (bisa memuat URL)
		}
	}
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	return strings.IndexByte(head, 0) >= 0
}

func scopeChecker(cfg *Config, scopeSrc string) func(string) bool {
	if cfg.Scope == "" && !cfg.ScopeExact.set && !(cfg.BaseScope && scopeSrc != "") {
		return nil
	}
	return func(h string) bool { return passScopeFilter(cfg, "https://"+urlHost(h)+"/", scopeSrc) }
}

func processItem(cfg *Config, item WorkItem, known *KnownSet) recResult {
	res := recResult{seq: item.seq}
	content, pageURL, ctype := item.Content, item.PageURL, item.ContentType
	if pageURL == "" {
		pageURL = item.URL
	}
	label := item.URL
	if !item.IsLocal {
		logVerbose(cfg, "Fetching: %s", item.URL)
		f, err := fetchContent(cfg, item.URL)
		if err != nil {
			logVerbose(cfg, "Error fetching %s: %v", item.URL, err)
			return res
		}
		content, pageURL, ctype = f.body, f.finalURL, f.contentType
	} else if label == "" {
		label = "local-file"
	}
	if content == "" || isBinaryContent(ctype, content) {
		return res
	}
	scopeSrc := ""
	if cfg.BaseScope {
		scopeSrc = scopeHostForItem(cfg, WorkItem{URL: pageURL})
	}
	r := Extract(content, ExtractOptions{
		SourceLabel:     label,
		PageURL:         pageURL,
		BaseOverride:    cfg.BaseURL,
		ContentType:     ctype,
		IncludeAssets:   cfg.IncludeAssets,
		IncludeExternal: cfg.IncludeExternal,
		InScope:         scopeChecker(cfg, scopeSrc),
	})
	logVerbose(cfg, "  %s base=%s endpoints=%d", label, r.Base, len(r.Endpoints))
	res.skipped = r.SkippedExternal
	res.refs, res.docOrigin = r.ScriptRefs, r.DocOrigin
	for _, ep := range r.Endpoints {
		ep.seq = item.seq
		if ep.PageRel && cfg.BaseURL == "" {
			res.pending = append(res.pending, ep)
			continue
		}
		if keepEndpoint(cfg, ep, known, item.URL) {
			res.eps = append(res.eps, ep)
		}
	}
	return res
}

// keepEndpoint: filter akhir (self, aset, scope, known).
func keepEndpoint(cfg *Config, ep Endpoint, known *KnownSet, srcURL string) bool {
	if ep.AbsURL == "" || ep.AbsURL == srcURL || ep.AbsURL == ep.PageURL {
		return false
	}
	if !cfg.IncludeAssets && strings.Contains(ep.AbsURL, "://") && isStaticAsset(ep.AbsURL) {
		return false
	}
	scopeSrc := ""
	if cfg.BaseScope {
		scopeSrc = scopeHostForItem(cfg, WorkItem{URL: ep.PageURL})
	}
	if !passScopeFilter(cfg, ep.AbsURL, scopeSrc) {
		return false
	}
	return !known.Contains(ep.AbsURL)
}

// scriptKey: identitas file JS (skema+host lowercase + path; query diabaikan).
func scriptKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + hostKey(u) + u.EscapedPath()
}

// reattribute: endpoint relatif-origin dari JS ditempel ke origin halaman yang
// memuat JS tsb (<script src> di record HTML). JS di CDN (cdn.vendor.net/app.js
// dimuat app.target.com) -> fetch("/api/x") = app.target.com/api/x, bukan CDN.
// JS yang tak direferensikan halaman mana pun: tetap origin file-nya.
func reattribute(pending []Endpoint, refs map[string]map[string]bool) []Endpoint {
	var out []Endpoint
	for _, ep := range pending {
		origins := refs[scriptKey(ep.PageURL)]
		if len(origins) == 0 {
			out = append(out, ep)
			continue
		}
		list := make([]string, 0, len(origins))
		for o := range origins {
			list = append(list, o)
		}
		sort.Strings(list)
		if len(list) > 5 {
			list = list[:5]
		}
		for _, o := range list {
			c := ep
			c.AbsURL = resolveAgainst(o, ep.RelPath)
			c.Interest = scoreInterest(c.AbsURL)
			out = append(out, c)
		}
	}
	return out
}

// readJSONLines: baca per-baris tanpa batas keras bufio.Scanner. Baris >max
// dilewati (dihitung) dan pembacaan berlanjut. fn=false -> berhenti.
func readJSONLines(r io.Reader, max int, fn func([]byte) bool) (skipped int, err error) {
	br := bufio.NewReaderSize(r, 1<<20)
	var buf []byte
	tooLong := false
	for {
		chunk, rerr := br.ReadSlice('\n')
		if len(chunk) > 0 && !tooLong {
			if len(buf)+len(chunk) > max {
				tooLong = true
				buf = nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if rerr == bufio.ErrBufferFull {
			continue
		}
		if tooLong {
			skipped++
		} else if line := bytes.TrimSpace(buf); len(line) > 0 {
			if !fn(line) {
				return skipped, nil
			}
		}
		tooLong = false
		if cap(buf) > 64<<20 {
			buf = nil // jangan tahan buffer raksasa
		} else {
			buf = buf[:0]
		}
		if rerr == io.EOF {
			return skipped, nil
		}
		if rerr != nil {
			return skipped, rerr
		}
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

type headerFlags []string

func (h *headerFlags) String() string     { return strings.Join(*h, ", ") }
func (h *headerFlags) Set(v string) error { *h = append(*h, v); return nil }

// boolFlags / valueFlags: daftar flag dikenal (untuk reorder argumen).
var boolFlags = map[string]bool{
	"json": true, "silent": true, "v": true, "verbose": true,
	"no-color": true, "no-source": true, "urls-only": true,
	"fuzz": true, "curl": true, "include-assets": true, "include-external": true,
	"bs": true, "base-scope": true, "scope-exact": true, "version": true,
}

var valueFlags = map[string]bool{
	"l": true, "list": true, "k": true, "known": true, "js": true,
	"httpx-json": true, "b": true, "base": true, "scope": true,
	"t": true, "threads": true, "delay": true, "rate": true, "ua": true,
	"flaresolverr": true, "o": true, "output": true, "out-prefix": true,
	"timeout": true, "body-format": true, "H": true, "header": true,
}

// reorderArgsForParsing memindahkan flag dikenal ke depan agar flag TETAP
// terbaca walau ditulis setelah URL posisional (Go flag berhenti di argumen
// posisional pertama). Token dash yang tidak dikenal dibiarkan apa adanya.
func reorderArgsForParsing(args []string) []string {
	var flags, positional []string
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		name := ""
		isFlag := len(a) > 1 && a[0] == '-' && a != "-"
		if isFlag {
			name = strings.TrimPrefix(a[1:], "-")
			if idx := strings.Index(name, "="); idx >= 0 {
				name = name[:idx]
			}
		}
		if isFlag && (boolFlags[name] || valueFlags[name]) {
			if name == "scope-exact" && !strings.Contains(a, "=") && i+1 < len(args) {
				// `--scope-exact api.x` (spasi): makan token berikut sbg domain,
				// KECUALI bila ia jelas URL target (ada :// atau /) atau flag.
				nxt := args[i+1]
				if nxt != "" && !strings.HasPrefix(nxt, "-") && !strings.Contains(nxt, "://") && !strings.Contains(nxt, "/") {
					i++
					flags = append(flags, "--scope-exact="+nxt)
				} else {
					flags = append(flags, a)
				}
			} else {
				flags = append(flags, a)
				if valueFlags[name] && !strings.Contains(a, "=") && i+1 < len(args) {
					i++
					flags = append(flags, args[i])
				}
			}
		} else if isFlag && len(a) > 2 && a[1] != '-' && valueFlags[a[1:2]] {
			// bentuk nempel: -oout.txt -> -o out.txt
			flags = append(flags, a[:2], a[2:])
		} else {
			positional = append(positional, a)
		}
		i++
	}
	return append(flags, positional...)
}

// normScopeArg: "https://*.Example.com:443/x" -> "example.com".
func normScopeArg(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSuffix(strings.TrimPrefix(hostOnly(s), "*."), ".")
}

// hostOnly: buang port & kurung IPv6 — "[::1]:80"->"::1", "h:80"->"h".
// IPv6 polos ("::1", "2001:db8::1") TIDAK dipotong: dulu ":1" dianggap port →
// scope ":" → semua endpoint target IPv6 terbuang.
func hostOnly(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			return s[1:i]
		}
		return strings.Trim(s, "[]")
	}
	if strings.Count(s, ":") == 1 {
		i := strings.LastIndex(s, ":")
		if _, err := strconv.Atoi(s[i+1:]); err == nil {
			return s[:i]
		}
	}
	return s
}

// urlHost: host untuk disisipkan ke URL — IPv6 wajib ber-kurung.
func urlHost(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

func readURLList(r io.Reader, into *[]string) error {
	_, err := readJSONLines(r, 1<<20, func(b []byte) bool {
		line := strings.TrimSpace(string(b))
		if line != "" && !strings.HasPrefix(line, "#") {
			*into = append(*into, line)
		}
		return true
	})
	return err
}

func main() { os.Exit(run()) }

func run() int {
	cfg := &Config{}
	var headers headerFlags
	var showVersion bool

	flag.StringVar(&cfg.ListFile, "l", "", "File containing list of URLs to scan")
	flag.StringVar(&cfg.ListFile, "list", "", "File containing list of URLs to scan")
	flag.StringVar(&cfg.KnownFile, "k", "", "Extra known-endpoints file to filter against")
	flag.StringVar(&cfg.KnownFile, "known", "", "Extra known-endpoints file to filter against")
	flag.StringVar(&cfg.LocalJS, "js", "", "Local JS file to analyze")
	flag.StringVar(&cfg.HTTPXJSON, "httpx-json", "", "Read {url,body} from httpx -json -irr JSONL (body-reuse, no fetch; - = stdin)")
	flag.StringVar(&cfg.BaseURL, "b", "", "Base URL for resolving relative paths")
	flag.StringVar(&cfg.BaseURL, "base", "", "Base URL for resolving relative paths")
	flag.StringVar(&cfg.Scope, "scope", "", "Only output endpoints on this domain + subdomains (D + *.D)")
	flag.Var(&cfg.ScopeExact, "scope-exact", "Exact host only: `--scope-exact api.x.com` (space/=), or bare modifier for --scope/-bs")
	flag.BoolVar(&cfg.BaseScope, "bs", false, "Auto-scope: registrable domain of input host (per source record)")
	flag.BoolVar(&cfg.BaseScope, "base-scope", false, "Alias of -bs")
	flag.IntVar(&cfg.Threads, "t", 20, "Number of concurrent threads")
	flag.IntVar(&cfg.Threads, "threads", 20, "Number of concurrent threads")
	flag.IntVar(&cfg.DelayMs, "delay", 0, "Delay between requests in milliseconds")
	flag.Float64Var(&cfg.RatePerSec, "rate", 0, "Max requests per second (0 = unlimited)")
	flag.StringVar(&cfg.UserAgent, "ua", defaultUA, "User-Agent string")
	flag.StringVar(&cfg.FlareSolvrURL, "flaresolverr", "", "FlareSolverr URL (e.g. http://localhost:8191)")
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file path (default/--urls-only: 1 URL per line)")
	flag.StringVar(&cfg.OutputFile, "output", "", "Output file path")
	flag.StringVar(&cfg.OutPrefix, "out-prefix", "", "Write <p>.txt (plain urls) + <p>.jsonl (rich) + <p>.curl.sh in one run")
	flag.BoolVar(&cfg.OutputJSON, "json", false, "Output as JSON")
	flag.IntVar(&cfg.Timeout, "timeout", 7, "Request timeout in seconds")
	flag.BoolVar(&cfg.Silent, "silent", false, "No banner or progress output")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose mode")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose mode")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI colors")
	flag.BoolVar(&cfg.NoSource, "no-source", false, "Hide source URL from output")
	flag.BoolVar(&cfg.URLsOnly, "urls-only", false, "Output only URLs, one per line (pipeline mode)")
	flag.BoolVar(&cfg.Fuzz, "fuzz", false, "Replace {param} placeholders with FUZZ in output")
	flag.BoolVar(&cfg.Curl, "curl", false, "Output ready-to-run curl commands")
	flag.StringVar(&cfg.BodyFormat, "body-format", "json", "Body format for non-GET curl: json|form|both")
	flag.BoolVar(&cfg.IncludeAssets, "include-assets", false, "Include static asset URLs (JS/CSS/images, dynamic import() chunks, sourcemaps)")
	flag.BoolVar(&cfg.IncludeExternal, "include-external", true, "Include URLs from external domains (default true; narrow with --scope/-bs)")
	flag.Var(&headers, "H", "Extra HTTP header \"Name: value\" (repeatable; sent on every request)")
	flag.Var(&headers, "header", "Extra HTTP header")
	flag.BoolVar(&showVersion, "version", false, "Print version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, banner, version)
		fmt.Fprintf(os.Stderr, "\nUsage:\n  endpoint-hunter2 [flags] [url...]  (flags may also follow URLs)\n")
		fmt.Fprintf(os.Stderr, "  endpoint-hunter2 --httpx-json valid-urls.json --scope example.com -k all-urls.txt\n\n")
		flag.PrintDefaults()
	}

	if len(os.Args) > 1 {
		os.Args = append([]string{os.Args[0]}, reorderArgsForParsing(os.Args[1:])...)
	}
	flag.Parse()
	if showVersion {
		fmt.Println(version)
		return 0
	}
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "ua" {
			cfg.UAExplicit = true
		}
	})

	cfg.ExtraHeaders = headers
	for _, b := range parseHeaders(cfg) {
		logErr("ignoring malformed -H %q (expected \"Name: value\")", b)
	}
	cfg.MaxBodyBytes = int64(maxBodyMB * 1024 * 1024)
	if cfg.BodyFormat != "form" && cfg.BodyFormat != "both" {
		cfg.BodyFormat = "json"
	}
	if cfg.Threads < 1 {
		cfg.Threads = 1 // -t 0 would deadlock (no workers, blocked feeder)
	}
	if cfg.Scope != "" {
		cfg.Scope = normScopeArg(cfg.Scope)
	}
	if cfg.ScopeExact.domain != "" {
		cfg.ScopeExact.domain = normScopeArg(cfg.ScopeExact.domain)
	}

	httpClient = buildClient(cfg)

	if !cfg.Silent && !cfg.URLsOnly {
		fmt.Fprintf(os.Stderr, banner, version)
	}

	// ── Collect input ──
	known := newKnownSet()
	var scanItems []WorkItem
	var jsonlIn io.Reader

	if cfg.HTTPXJSON != "" {
		if cfg.HTTPXJSON == "-" {
			jsonlIn = os.Stdin
		} else {
			f, err := os.Open(cfg.HTTPXJSON)
			if err != nil {
				logErr("error opening httpx-json: %v", err)
				return 1
			}
			defer f.Close()
			jsonlIn = f
		}
	} else {
		cfg.URLs = append(cfg.URLs, flag.Args()...)
		if len(cfg.URLs) == 0 && cfg.ListFile == "" && cfg.LocalJS == "" {
			if stat, err := os.Stdin.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
				if err := readURLList(os.Stdin, &cfg.URLs); err != nil {
					logErr("error reading stdin: %v", err)
					return 1
				}
			}
		}
		if cfg.ListFile != "" {
			f, err := os.Open(cfg.ListFile)
			if err != nil {
				logErr("error opening list file: %v", err)
				return 1
			}
			err = readURLList(f, &cfg.URLs)
			f.Close()
			if err != nil {
				logErr("error reading list file: %v", err)
				return 1
			}
		}
		for _, u := range cfg.URLs {
			scanItems = append(scanItems, WorkItem{URL: u})
		}
		if cfg.LocalJS != "" {
			f, err := os.Open(cfg.LocalJS)
			if err != nil {
				logErr("error reading JS file: %v", err)
				return 1
			}
			data, err := io.ReadAll(io.LimitReader(f, cfg.MaxBodyBytes))
			f.Close()
			if err != nil {
				logErr("error reading JS file: %v", err)
				return 1
			}
			if bytes.IndexByte(data, 0) != -1 {
				logErr("%s looks binary, refusing to scan", cfg.LocalJS)
				return 1
			}
			scanItems = append(scanItems, WorkItem{URL: cfg.LocalJS, PageURL: cfg.BaseURL, IsLocal: true, Content: string(data)})
		}
		if len(scanItems) == 0 {
			logErr("no input. Use -l list.txt, -js file.js, --httpx-json file, or pipe URLs via stdin.")
			flag.Usage()
			return 1
		}
		hasLocal := false
		for _, item := range scanItems {
			if !item.IsLocal {
				known.Add(item.URL) // input URL otomatis known
			} else {
				hasLocal = true
			}
		}
		if hasLocal && cfg.BaseURL == "" {
			logWarn(cfg, "local JS without -b/--base: relative paths stay relative; --scope and absolute known-entries won't apply to them")
		}
	}

	if cfg.KnownFile != "" {
		f, err := os.Open(cfg.KnownFile)
		if err != nil {
			logErr("error opening known file: %v", err)
			return 1
		}
		var lines []string
		err = readURLList(f, &lines)
		f.Close()
		if err != nil {
			logErr("error reading known file: %v", err)
			return 1
		}
		for _, l := range lines {
			known.Add(l)
		}
	}

	if cfg.HTTPXJSON != "" {
		logInfo(cfg, "%s[*]%s Mode: httpx-json body-reuse (%s) | %d known", cCyan, cReset, cfg.HTTPXJSON, known.Size())
	} else {
		logInfo(cfg, "%s[*]%s Scanning %d URL(s) | %d known endpoints to filter", cCyan, cReset, len(scanItems), known.Size())
	}

	// ── Interrupt: sinyal pertama = berhenti rapi (hasil parsial tetap
	// ditulis, exit 130); sinyal kedua = keluar paksa.
	var stopping atomic.Bool
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		stopping.Store(true)
		logErr("interrupted — finishing in-flight work and writing partial results (Ctrl-C again to abort)")
		<-sigCh
		os.Exit(130)
	}()

	workCh := make(chan WorkItem, cfg.Threads)
	var (
		mu      sync.Mutex
		results []recResult
		wg      sync.WaitGroup
		done    int64
		skipExt int64
	)
	rl := newRateLimiter(cfg.RatePerSec)
	defer rl.Stop()

	total := int64(len(scanItems))
	printProgress := func() {
		if cfg.Silent {
			return
		}
		cur := atomic.LoadInt64(&done)
		if total > 0 {
			fmt.Fprintf(os.Stderr, "\r%s[*]%s Progress: %d/%d (%d%%)   ", cCyan, cReset, cur, total, int(float64(cur)/float64(total)*100))
		} else {
			fmt.Fprintf(os.Stderr, "\r%s[*]%s Processed: %d   ", cCyan, cReset, cur)
		}
	}

	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workCh {
				if stopping.Load() {
					continue // kuras antrean tanpa kerja
				}
				if !item.IsLocal {
					if rl == nil {
						if cfg.DelayMs > 0 {
							time.Sleep(time.Duration(cfg.DelayMs) * time.Millisecond)
						}
					} else {
						rl.Wait() // rate-limiter aktif -> delay tidak ditumpuk
					}
				}
				r := processItem(cfg, item, known)
				atomic.AddInt64(&skipExt, int64(r.skipped))
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
				atomic.AddInt64(&done, 1)
				printProgress()
			}
		}()
	}

	// Feeder (streaming untuk httpx-json)
	var inErr error
	var skippedLines, badLines, binLines int
	seq := 0
	if jsonlIn != nil {
		skippedLines, inErr = readJSONLines(jsonlIn, maxJSONLLine, func(line []byte) bool {
			if stopping.Load() {
				return false
			}
			var rec httpxRecord
			if json.Unmarshal(line, &rec) != nil {
				badLines++
				return true
			}
			if rec.URL == "" || rec.Body == "" {
				return true
			}
			if isBinaryContent(rec.ContentType, rec.Body) {
				binLines++
				return true
			}
			if int64(len(rec.Body)) > cfg.MaxBodyBytes {
				rec.Body = rec.Body[:cfg.MaxBodyBytes] // konsisten dgn batas fetch mode
			}
			pageURL := rec.URL
			if rec.FinalURL != "" {
				pageURL = rec.FinalURL // base resolusi = URL setelah redirect
			}
			workCh <- WorkItem{URL: rec.URL, PageURL: pageURL, IsLocal: true, Content: rec.Body, ContentType: rec.ContentType, seq: seq}
			seq++
			return true
		})
	} else {
		for _, item := range scanItems {
			if stopping.Load() {
				break
			}
			item.seq = seq
			seq++
			workCh <- item
		}
	}
	close(workCh)
	wg.Wait()
	if !cfg.Silent {
		fmt.Fprintln(os.Stderr)
	}
	if inErr != nil {
		logErr("error reading %s: %v (results are partial)", cfg.HTTPXJSON, inErr)
	}
	if skippedLines > 0 {
		logErr("skipped %d JSONL line(s) larger than %d MB", skippedLines, maxJSONLLine>>20)
	}
	if badLines > 0 {
		logWarn(cfg, "%d malformed JSONL line(s) ignored", badLines)
	}
	if binLines > 0 {
		logVerbose(cfg, "%d binary record(s) skipped", binLines)
	}
	if n := atomic.LoadInt64(&skipExt); n > 0 {
		logInfo(cfg, "%s[i]%s %d absolute URL(s) skipped as external -- re-run with --include-external (or --scope <domain>) to include", cDim, cReset, n)
	}

	// ── Gabung deterministik (urutan input), atribusi ulang CDN ──
	sort.Slice(results, func(i, j int) bool { return results[i].seq < results[j].seq })
	refs := map[string]map[string]bool{}
	var all, pending []Endpoint
	for _, r := range results {
		all = append(all, r.eps...)
		pending = append(pending, r.pending...)
		if r.docOrigin == "" {
			continue
		}
		for _, s := range r.refs {
			k := scriptKey(s)
			if k == "" {
				continue
			}
			if refs[k] == nil {
				refs[k] = map[string]bool{}
			}
			refs[k][r.docOrigin] = true
		}
	}
	for _, ep := range reattribute(pending, refs) {
		if keepEndpoint(cfg, ep, known, ep.PageURL) {
			all = append(all, ep)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].seq != all[j].seq {
			return all[i].seq < all[j].seq
		}
		return all[i].pos < all[j].pos
	})
	allFound := mergeEndpoints(all)

	// ── Sort & Output ──
	interestOrder := map[string]int{"HIGH": 0, "MED": 1, "LOW": 2}
	sort.SliceStable(allFound, func(i, j int) bool {
		oi, oj := interestOrder[allFound[i].Interest], interestOrder[allFound[j].Interest]
		if oi != oj {
			return oi < oj
		}
		if allFound[i].AbsURL != allFound[j].AbsURL {
			return allFound[i].AbsURL < allFound[j].AbsURL
		}
		return allFound[i].Method < allFound[j].Method
	})

	outURL := func(ep Endpoint) string {
		if cfg.Fuzz {
			return enrichEndpoint(ep).URL
		}
		return ep.AbsURL
	}
	uniqueURLs := func() []string {
		seen := map[string]bool{}
		var out []string
		for _, ep := range allFound {
			u := outURL(ep)
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
		return out
	}

	var fileLines []string
	switch {
	case cfg.OutputJSON:
		results := []Result{}
		for _, ep := range allFound {
			e := enrichEndpoint(ep)
			results = append(results, toResult(ep, outURL(ep), e.Body))
		}
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
		fileLines = []string{string(data)}
	case cfg.URLsOnly:
		fileLines = uniqueURLs()
		for _, u := range fileLines {
			fmt.Println(u)
		}
	case cfg.Curl:
		for _, ep := range allFound {
			for _, cl := range buildCurl(ep, cfg.BodyFormat) {
				fmt.Println(cl)
				fileLines = append(fileLines, cl)
			}
		}
	default:
		if len(allFound) == 0 {
			logInfo(cfg, "%s[-]%s No new endpoints found.", cDim, cReset)
		} else {
			logInfo(cfg, "%s[+]%s Found %d new endpoint(s):\n", cGreen, cReset, len(allFound))
			for _, ep := range allFound {
				ep.AbsURL = outURL(ep)
				fmt.Println(printEndpoint(cfg, ep))
			}
		}
		// File -o pada mode tabel = 1 URL absolut per baris (kontrak pipeline:
		// dibaca uro/httpx -l/secrethunter2). Dulu baris tabel "[HIGH] GET url ← src".
		fileLines = uniqueURLs()
	}

	rc := 0
	if cfg.OutPrefix != "" {
		if err := writeMultiStream(cfg, allFound); err != nil {
			logErr("%v", err)
			rc = 1
		}
	}
	if cfg.OutputFile != "" {
		// selalu ditulis (juga saat kosong) agar file basi run sebelumnya tidak terbaca ulang
		if err := writeLinesFile(cfg.OutputFile, fileLines); err != nil {
			logErr("%v", err)
			rc = 1
		} else {
			logInfo(cfg, "\n%s[+]%s Saved to %s", cGreen, cReset, cfg.OutputFile)
		}
	}

	logInfo(cfg, "\n%s[*]%s Done. %d new endpoint(s) discovered.", cCyan, cReset, len(allFound))
	if inErr != nil {
		rc = 1
	}
	if stopping.Load() {
		return 130
	}
	return rc
}

// applyFuzz replaces all {param} placeholders with FUZZ
var rePlaceholder = regexp.MustCompile(`\{[^}]+\}`)

func applyFuzz(u string) string {
	return rePlaceholder.ReplaceAllString(u, "FUZZ")
}

// twoPartPublicSuffix: suffix publik 2-label umum — bila 2-label terakhir
// cocok, pakai 3 label agar evil.co.id != target.co.id.
var twoPartPublicSuffix = map[string]bool{
	"ac.id": true, "co.id": true, "or.id": true, "go.id": true,
	"mil.id": true, "net.id": true, "web.id": true, "my.id": true,
	"biz.id": true, "ponpes.id": true, "sch.id": true, "co.uk": true, "org.uk": true,
	"me.uk": true, "ltd.uk": true, "plc.uk": true, "ac.uk": true, "gov.uk": true, "com.au": true,
	"net.au": true, "org.au": true, "co.jp": true, "ne.jp": true,
	"or.jp": true, "co.in": true, "com.br": true, "com.sg": true,
	"co.za": true, "com.my": true, "com.cn": true, "com.tr": true, "com.mx": true,
	"co.kr": true, "co.nz": true, "com.vn": true, "com.ph": true,
}

// registrableDomain: aproksimasi (api.apps.binus.ac.id -> binus.ac.id).
// IP/v6 kembali utuh, port dibuang.
func registrableDomain(host string) string {
	h := strings.TrimSuffix(hostOnly(strings.ToLower(host)), ".")
	if strings.Contains(h, ":") {
		return h // IPv6 -> utuh
	}
	parts := strings.Split(h, ".")
	allNum := len(parts) == 4
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			allNum = false
			break
		}
	}
	if allNum {
		return h // IPv4 -> utuh
	}
	if len(parts) >= 2 {
		last2 := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if twoPartPublicSuffix[last2] && len(parts) >= 3 {
			return parts[len(parts)-3] + "." + last2
		}
		return last2
	}
	return h
}

// scopeHostForItem: host acuan mode -bs — -b bila ada, else host URL sumber.
func scopeHostForItem(cfg *Config, item WorkItem) string {
	if cfg.BaseURL != "" {
		return extractHost(cfg.BaseURL)
	}
	if strings.HasPrefix(item.URL, "http://") || strings.HasPrefix(item.URL, "https://") {
		return extractHost(item.URL)
	}
	return ""
}

// exactScopeValue: --scope-exact dua bentuk —
//
//	bare (`--scope-exact`)         -> modifier: exact-kan --scope / -bs
//	nilai (`--scope-exact=api.x`)  -> tepat host itu (single-flag, tanpa --scope)
type exactScopeValue struct {
	set      bool
	modifier bool
	domain   string
}

func (v *exactScopeValue) String() string { return v.domain }
func (v *exactScopeValue) Set(s string) error {
	v.set = true
	switch {
	case s == "true":
		v.modifier = true
	case s == "false":
		v.set, v.modifier, v.domain = false, false, ""
	default:
		v.domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	}
	return nil
}
func (v *exactScopeValue) IsBoolFlag() bool { return true }

func normScopeHost(scope string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(hostOnly(scope), "*."), "."))
}

// passScopeFilter: default luas (tanpa flag scope -> semua lolos).
// --scope D [+ --scope-exact] dan -bs (union) — lolos bila SALAH SATU cocok.
func passScopeFilter(cfg *Config, absURL, scopeSrcHost string) bool {
	h := extractHost(absURL)
	ex := cfg.ScopeExact
	if ex.set && ex.domain != "" {
		if h != "" && h == ex.domain {
			return true
		}
	}
	if ex.set && ex.domain == "" && ex.modifier {
		if cfg.Scope != "" {
			return h != "" && h == normScopeHost(cfg.Scope)
		}
		if scopeSrcHost != "" {
			return h != "" && h == strings.ToLower(scopeSrcHost)
		}
	}
	if cfg.Scope != "" && matchesScope(absURL, cfg.Scope) {
		return true
	}
	if cfg.BaseScope && scopeSrcHost != "" && h != "" {
		rh, rs := registrableDomain(h), registrableDomain(scopeSrcHost)
		if rh != "" && rh == rs {
			return true
		}
	}
	if cfg.Scope == "" && scopeSrcHost == "" && !(ex.set && ex.domain != "") {
		return true
	}
	return false
}

func matchesScope(rawURL, scope string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	scope = normScopeHost(scope)
	return host != "" && (host == scope || strings.HasSuffix(host, "."+scope))
}

// stripANSI removes ANSI escape codes for clean file output
func stripANSI(s string) string {
	var result []byte
	inEscape := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if s[i] == 'm' {
				inEscape = false
			}
			continue
		}
		result = append(result, s[i])
	}
	return string(result)
}

// ─── multi-stream output (pipelineable) ──────────────────────────────────────
//
//	<p>.txt      AbsURL unik, 1 per baris    → httpx/ffuf/nuclei/secrethunter2
//	<p>.jsonl    1 record per (url, method)  → api-catcher -ej / jq
//	<p>.curl.sh  ready-to-run curl commands  → manual testing
func writeMultiStream(cfg *Config, eps []Endpoint) error {
	var urls, jsonls, curls []string
	seen := map[string]bool{}
	for _, ep := range eps {
		e := enrichEndpoint(ep)
		u := ep.AbsURL
		if cfg.Fuzz {
			u = e.URL
		}
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
		b, _ := json.Marshal(toResult(ep, u, e.Body))
		jsonls = append(jsonls, string(b))
		curls = append(curls, buildCurl(ep, cfg.BodyFormat)...)
	}
	var errs []error
	for _, w := range []struct {
		p string
		l []string
	}{{cfg.OutPrefix + ".txt", urls}, {cfg.OutPrefix + ".jsonl", jsonls}, {cfg.OutPrefix + ".curl.sh", curls}} {
		if err := writeLinesFile(w.p, w.l); err != nil {
			errs = append(errs, err)
		}
	}
	logInfo(cfg, "%s[+]%s Multi-stream: %s.txt (%d) · %s.jsonl (%d) · %s.curl.sh",
		cGreen, cReset, cfg.OutPrefix, len(urls), cfg.OutPrefix, len(jsonls), cfg.OutPrefix)
	return errors.Join(errs...)
}

// writeLinesFile: tulis atomik-ish (buffer + cek error Close).
func writeLinesFile(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating %s: %w", path, err)
	}
	w := bufio.NewWriterSize(f, 1<<16)
	for _, l := range lines {
		w.WriteString(l)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return fmt.Errorf("error writing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("error writing %s: %w", path, err)
	}
	return nil
}
