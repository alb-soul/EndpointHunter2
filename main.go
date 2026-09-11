package main

// ============================================================
// endpoint-hunter2 — main.go (patched)
//
// Build (dir terpisah, package: main.go + extractor.go + enrich.go + go.mod):
//   go build -o endpoint-hunter2 .
//
// PERUBAHAN vs v1:
//   * --httpx-json <file> : baca {url, body} dari httpx -json -irr dan ekstrak
//     endpoint dari body TANPA fetch ulang (body-reuse). URL asli tetap dipakai
//     sebagai base → resolusi path relatif & source akurat. Streaming.
//   * Shared HTTP transport (keep-alive per-host).
//   * FlareSolverr re-solve saat 403/429 (cookie expired) di fetchContent.
//   * (extractor.go) regex hoist + whole-content scan + window konteks char.
// ============================================================

import (
	"bufio"
	"bytes"
	"encoding/json"
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
	version   = "2.0.1"
	defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	maxBodyMB = 10
	banner    = `
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
	HTTPXJSON       string          // v2: JSONL dari httpx -json -irr
	Threads         int
	DelayMs         int
	RatePerSec      float64
	UserAgent       string
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

func (fc *FSCache) Resolve(cfg *Config, domain string) *FSSession {
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
		sess := solveDomain(cfg, domain)
		fc.mu.Lock()
		fc.sessions[domain] = sess
		fc.mu.Unlock()
	})

	fc.mu.RLock()
	s := fc.sessions[domain]
	fc.mu.RUnlock()
	return s
}

// Invalidate menghapus sesi domain agar Resolve berikutnya solve ulang (v2).
func (fc *FSCache) Invalidate(domain string) {
	fc.mu.Lock()
	delete(fc.sessions, domain)
	delete(fc.solving, domain)
	fc.mu.Unlock()
}

// fsClient: client khusus FlareSolverr dengan timeout lebih panjang (solve bisa
// 40-60s) dan transport sendiri, TIDAK bergantung pada httpClient yang Timeout-nya
// mengikuti --timeout (default 7s) — http.Post bawaan (tanpa timeout) ditinggalkan.
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

func solveDomain(cfg *Config, domain string) *FSSession {
	targetURL := "https://" + domain

	body, _ := json.Marshal(fsRequest{
		Cmd:        "request.get",
		URL:        targetURL,
		MaxTimeout: 60000,
	})

	resp, err := fsClient.Post(strings.TrimRight(cfg.FlareSolvrURL, "/")+"/v1", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var fsResp fsResponse
	if err := json.NewDecoder(resp.Body).Decode(&fsResp); err != nil {
		return nil
	}
	if fsResp.Status != "ok" {
		return nil
	}

	var cookieParts []string
	for _, c := range fsResp.Solution.Cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	return &FSSession{
		Cookies:   strings.Join(cookieParts, "; "),
		UserAgent: fsResp.Solution.UserAgent,
	}
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

func fetchContent(cfg *Config, rawURL string) (string, error) {
	u, _ := url.Parse(rawURL)
	host := ""
	if u != nil {
		host = u.Host
	}

	for attempt := 0; attempt < 2; attempt++ {
		ua := cfg.UserAgent
		var cookies string
		if cfg.FlareSolvrURL != "" && host != "" {
			if sess := fsCache.Resolve(cfg, host); sess != nil {
				if sess.UserAgent != "" {
					ua = sess.UserAgent
				}
				cookies = sess.Cookies
			}
		}

		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		if cookies != "" {
			req.Header.Set("Cookie", cookies)
		}
		for _, h := range cfg.ExtraHeaders {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", err
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			resp.Body.Close()
			if cfg.FlareSolvrURL != "" && host != "" && attempt == 0 {
				fsCache.Invalidate(host)
				continue
			}
			return "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			resp.Body.Close()
			return "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		limited := io.LimitReader(resp.Body, cfg.MaxBodyBytes)
		data, err := io.ReadAll(limited)
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	return "", fmt.Errorf("blocked after retry")
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
	if cfg.NoColor {
		return fmt.Sprintf("%-7s", method)
	}
	m := fmt.Sprintf("%-7s", method)
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
	interest := colorInterest(cfg, ep.Interest)
	method := colorMethod(cfg, ep.Method)
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
	return fmt.Sprintf("[%s] %s %s%s%s", interest, method, epURL, params, src)
}

// ─── Known URL Filter ─────────────────────────────────────────────────────────

type KnownSet struct {
	paths map[string]bool
	full  map[string]bool
}

func newKnownSet() *KnownSet {
	return &KnownSet{
		paths: make(map[string]bool),
		full:  make(map[string]bool),
	}
}

func (ks *KnownSet) Add(rawURL string) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return
	}
	ks.full[dedupKey(rawURL)] = true
	ks.paths[normaliseForFilter(rawURL)] = true
}

func (ks *KnownSet) Contains(rawURL string) bool {
	if ks.full[dedupKey(rawURL)] {
		return true
	}
	return ks.paths[normaliseForFilter(rawURL)]
}

func (ks *KnownSet) Size() int {
	return len(ks.full)
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

type RateLimiter struct {
	ticker *time.Ticker
	done   chan struct{}
}

func newRateLimiter(rps float64) *RateLimiter {
	if rps <= 0 {
		return nil
	}
	interval := time.Duration(float64(time.Second) / rps)
	return &RateLimiter{
		ticker: time.NewTicker(interval),
		done:   make(chan struct{}),
	}
}

func (r *RateLimiter) Wait() {
	if r == nil {
		return
	}
	<-r.ticker.C
}

func (r *RateLimiter) Stop() {
	if r == nil {
		return
	}
	r.ticker.Stop()
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

// ─── Result ───────────────────────────────────────────────────────────────────

type Result struct {
	URL      string   `json:"url"`
	Method   string   `json:"method"`
	Params   []string `json:"params,omitempty"`
	Body     []string `json:"body_params,omitempty"`
	Interest string   `json:"interest"`
	Source   string   `json:"source"`
}

// ─── Worker ───────────────────────────────────────────────────────────────────

type WorkItem struct {
	URL     string
	IsLocal bool
	Content string
}

// httpxRecord: baris JSONL httpx -json -irr
type httpxRecord struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"`
}

func processURL(cfg *Config, item WorkItem, known *KnownSet, baseURL string) []Endpoint {
	var content string
	var err error
	sourceURL := item.URL

	if item.IsLocal {
		content = item.Content
		if sourceURL == "" {
			sourceURL = "local-file"
		}
	} else {
		logVerbose(cfg, "Fetching: %s", item.URL)
		content, err = fetchContent(cfg, item.URL)
		if err != nil {
			logVerbose(cfg, "Error fetching %s: %v", item.URL, err)
			return nil
		}
	}

	raw, detectedBase, skippedExt := extractEndpoints(content, sourceURL, item.URL, baseURL, cfg.IncludeAssets, cfg.IncludeExternal)
	logVerbose(cfg, "  Base URL: %s", detectedBase)
	if skippedExt > 0 {
		logInfo(cfg, "%s[i]%s %d absolute URL(s) skipped as external (base %s) -- re-run with --include-external (or --scope <domain>) to include", cDim, cReset, skippedExt, detectedBase)
	}

	scopeSrc := ""
	if cfg.BaseScope {
		scopeSrc = scopeHostForItem(cfg, item)
	}
	var results []Endpoint
	for _, ep := range raw {
		if ep.AbsURL == "" || ep.AbsURL == item.URL {
			continue
		}
		if !passScopeFilter(cfg, ep.AbsURL, scopeSrc) {
			continue
		}
		if known.Contains(ep.AbsURL) {
			continue
		}
		results = append(results, ep)
	}
	return results
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
	"bs": true, "base-scope": true, "scope-exact": true,
}

var valueFlags = map[string]bool{
	"l": true, "list": true, "k": true, "known": true, "js": true,
	"httpx-json": true, "b": true, "base": true, "scope": true,
	"t": true, "threads": true, "delay": true, "rate": true, "ua": true,
	"flaresolverr": true, "o": true, "output": true, "out-prefix": true,
	"timeout": true, "body-format": true, "H": true, "header": true,
}

// reorderArgsForParsing memindahkan flag dikenal ke depan agar flag TETAP
// terbaca walau ditulis setelah URL posisional.
// BUGFIX: Go flag berhenti parse di argumen posisional pertama —
// `endpoint-hunter2 <url> -o out` membuat "-o out" dianggap URL target
// (file tidak tertulis, URL sampah ikut di-fetch).
// Token dash yang tidak dikenal dibiarkan apa adanya (tidak diutak-atik).
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
			name = a[1:]
			if strings.HasPrefix(name, "-") {
				name = name[1:]
			}
			if idx := strings.Index(name, "="); idx >= 0 {
				name = name[:idx]
			}
		}
		if isFlag && (boolFlags[name] || valueFlags[name]) {
			if name == "scope-exact" && !strings.Contains(a, "=") && i+1 < len(args) {
				// `--scope-exact api.x` (spasi): makan token berikut sbg domain,
				// KECUALI bila ia jelas URL target (ada :// atau /) atau flag.
				// Bentuk `=` (`--scope-exact=api.x`) selalu aman & disarankan.
				nxt := args[i+1]
				if nxt != "" && !strings.HasPrefix(nxt, "-") && !strings.Contains(nxt, "://") && !strings.Contains(nxt, "/") {
					i++
					flags = append(flags, "--scope-exact="+nxt)
				} else {
					flags = append(flags, a)
				}
			} else {
				flags = append(flags, a)
				if valueFlags[name] && !strings.Contains(a, "=") {
					if i+1 < len(args) {
						i++
						flags = append(flags, args[i])
					}
				}
			}
		} else if isFlag && len(a) > 2 && a[0] == '-' && a[1] != '-' && valueFlags[a[1:2]] {
			// bentuk nempel: -oout.txt -> -o out.txt
			flags = append(flags, a[:2], a[2:])
		} else {
			positional = append(positional, a)
		}
		i++
	}
	return append(flags, positional...)
}

func main() {
	cfg := &Config{}
	var headers headerFlags

	flag.StringVar(&cfg.ListFile, "l", "", "File containing list of URLs to scan")
	flag.StringVar(&cfg.ListFile, "list", "", "File containing list of URLs to scan")
	flag.StringVar(&cfg.KnownFile, "k", "", "Extra known-endpoints file to filter against")
	flag.StringVar(&cfg.KnownFile, "known", "", "Extra known-endpoints file to filter against")
	flag.StringVar(&cfg.LocalJS, "js", "", "Local JS file to analyze")
	flag.StringVar(&cfg.HTTPXJSON, "httpx-json", "", "Read {url,body} from httpx -json -irr JSONL (body-reuse, no fetch)")
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
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file path")
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
	flag.BoolVar(&cfg.IncludeAssets, "include-assets", false, "Include static asset URLs (JS/CSS/images)")
	flag.BoolVar(&cfg.IncludeExternal, "include-external", true, "Include URLs from external domains (default true; narrow with --scope/-bs)")
	flag.Var(&headers, "H", "Extra HTTP header (repeatable)")
	flag.Var(&headers, "header", "Extra HTTP header")

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

	cfg.ExtraHeaders = headers
	cfg.MaxBodyBytes = int64(maxBodyMB * 1024 * 1024)
	if cfg.BodyFormat != "form" && cfg.BodyFormat != "both" {
		cfg.BodyFormat = "json"
	}
	if cfg.Threads < 1 {
		cfg.Threads = 1 // -t 0 would deadlock (no workers, blocked feeder)
	}

	httpClient = buildClient(cfg)

	if !cfg.Silent && !cfg.URLsOnly {
		fmt.Fprintf(os.Stderr, banner, version)
	}

	// ── Collect input URLs (mode fetch/local) ──
	known := newKnownSet()
	var scanItems []WorkItem

	if cfg.HTTPXJSON == "" {
		for _, u := range flag.Args() {
			cfg.URLs = append(cfg.URLs, u)
		}
		stat, _ := os.Stdin.Stat()
		if len(cfg.URLs) == 0 && cfg.ListFile == "" && cfg.LocalJS == "" && (stat.Mode()&os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					cfg.URLs = append(cfg.URLs, line)
				}
			}
		}
		if cfg.ListFile != "" {
			f, err := os.Open(cfg.ListFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening list file: %v\n", err)
				os.Exit(1)
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					cfg.URLs = append(cfg.URLs, line)
				}
			}
			f.Close()
		}
		for _, u := range cfg.URLs {
			scanItems = append(scanItems, WorkItem{URL: u})
		}
		if cfg.LocalJS != "" {
			f, err := os.Open(cfg.LocalJS)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading JS file: %v\n", err)
				os.Exit(1)
			}
			data, err := io.ReadAll(io.LimitReader(f, cfg.MaxBodyBytes))
			f.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading JS file: %v\n", err)
				os.Exit(1)
			}
			if bytes.IndexByte(data, 0) != -1 {
				fmt.Fprintf(os.Stderr, "Error: %s looks binary, refusing to scan\n", cfg.LocalJS)
				os.Exit(1)
			}
			scanItems = append(scanItems, WorkItem{URL: cfg.LocalJS, IsLocal: true, Content: string(data)})
		}
		if len(scanItems) == 0 {
			fmt.Fprintf(os.Stderr, "No input. Use -l list.txt, -js file.js, --httpx-json file, or pipe URLs via stdin.\n")
			flag.Usage()
			os.Exit(1)
		}
		// default: input URLs auto-known
		hasLocal := false
		for _, item := range scanItems {
			if !item.IsLocal {
				known.Add(item.URL)
			} else {
				hasLocal = true
			}
		}
		if hasLocal && cfg.BaseURL == "" {
			logWarn(cfg, "local JS without -b/--base: relative paths stay relative; --scope and absolute known-entries won't apply to them")
		}
	}

	// Additional known file (-k)
	if cfg.KnownFile != "" {
		f, err := os.Open(cfg.KnownFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening known file: %v\n", err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 8*1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				known.Add(line)
			}
		}
		f.Close()
	}

	if cfg.HTTPXJSON != "" {
		logInfo(cfg, "%s[*]%s Mode: httpx-json body-reuse (%s) | %d known", cCyan, cReset, cfg.HTTPXJSON, known.Size())
	} else {
		logInfo(cfg, "%s[*]%s Scanning %d URL(s) | %d known endpoints to filter", cCyan, cReset, len(scanItems), known.Size())
	}

	// ── Scan ──
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	workCh := make(chan WorkItem, cfg.Threads)

	var (
		mu       sync.Mutex
		allFound []Endpoint
		wg       sync.WaitGroup
	)
	globalSeen := make(map[string]bool)
	rl := newRateLimiter(cfg.RatePerSec)
	defer rl.Stop()

	var total int64
	if cfg.HTTPXJSON == "" {
		total = int64(len(scanItems))
	}
	var done int64

	printProgress := func() {
		if cfg.Silent {
			return
		}
		cur := atomic.LoadInt64(&done)
		if total > 0 {
			pct := int(float64(cur) / float64(total) * 100)
			fmt.Fprintf(os.Stderr, "\r%s[*]%s Progress: %d/%d (%d%%)   ", cCyan, cReset, cur, total, pct)
		} else {
			fmt.Fprintf(os.Stderr, "\r%s[*]%s Processed: %d   ", cCyan, cReset, cur)
		}
	}

	// Workers
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workCh {
				if !item.IsLocal {
					if rl == nil {
						// tanpa rate-limiter → delay per request
						if cfg.DelayMs > 0 {
							time.Sleep(time.Duration(cfg.DelayMs) * time.Millisecond)
						}
					} else {
						// rate-limiter aktif → delay TIDAK ditumpuk (hindari double-limit)
						rl.Wait()
					}
				}
				found := processURL(cfg, item, known, cfg.BaseURL)
				mu.Lock()
				for _, ep := range found {
					key := dedupKey(ep.AbsURL)
					if !globalSeen[key] {
						globalSeen[key] = true
						allFound = append(allFound, ep)
					}
				}
				mu.Unlock()
				atomic.AddInt64(&done, 1)
				printProgress()
			}
		}()
	}

	// Feeder (streaming untuk httpx-json, pre-list untuk mode lain)
	go func() {
		defer close(workCh)
		if cfg.HTTPXJSON != "" {
			var input io.Reader
			if cfg.HTTPXJSON == "-" {
				input = os.Stdin
			} else {
				f, err := os.Open(cfg.HTTPXJSON)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error opening httpx-json: %v\n", err)
					return
				}
				defer f.Close()
				input = f
			}
			sc := bufio.NewScanner(input)
			sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
			for sc.Scan() {
				line := sc.Bytes()
				if len(line) == 0 {
					continue
				}
				var rec httpxRecord
				if json.Unmarshal(line, &rec) != nil {
					continue
				}
				if rec.URL == "" || rec.Body == "" {
					continue
				}
				select {
				case <-sigCh:
					return
				case workCh <- WorkItem{URL: rec.URL, IsLocal: true, Content: rec.Body}:
				}
			}
			return
		}
		for _, item := range scanItems {
			select {
			case <-sigCh:
				return
			case workCh <- item:
			}
		}
	}()

	wg.Wait()
	if !cfg.Silent {
		fmt.Fprintln(os.Stderr)
	}

	// ── Sort & Output ──
	interestOrder := map[string]int{"HIGH": 0, "MED": 1, "LOW": 2}
	sort.Slice(allFound, func(i, j int) bool {
		oi := interestOrder[allFound[i].Interest]
		oj := interestOrder[allFound[j].Interest]
		if oi != oj {
			return oi < oj
		}
		return allFound[i].AbsURL < allFound[j].AbsURL
	})

	var outputLines []string

	if cfg.OutputJSON {
		var results []Result
		for _, ep := range allFound {
			e := enrichEndpoint(ep)
			u := ep.AbsURL
			if cfg.Fuzz {
				u = e.URL
			}
			results = append(results, Result{
				URL:      u,
				Method:   ep.Method,
				Params:   ep.Params,
				Body:     e.Body,
				Interest: ep.Interest,
				Source:   ep.Source,
			})
		}
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
		outputLines = []string{string(data)}
	} else if cfg.URLsOnly {
		for _, ep := range allFound {
			u := ep.AbsURL
			if cfg.Fuzz {
				u = enrichEndpoint(ep).URL
			}
			fmt.Println(u)
			outputLines = append(outputLines, u)
		}
	} else if cfg.Curl {
		for _, ep := range allFound {
			for _, cl := range buildCurl(ep, cfg.BodyFormat) {
				fmt.Println(cl)
				outputLines = append(outputLines, cl)
			}
		}
	} else {
		if len(allFound) == 0 {
			logInfo(cfg, "%s[-]%s No new endpoints found.", cDim, cReset)
		} else {
			logInfo(cfg, "%s[+]%s Found %d new endpoint(s):\n", cGreen, cReset, len(allFound))
			for _, ep := range allFound {
				if cfg.Fuzz {
					ep.AbsURL = enrichEndpoint(ep).URL
				}
				line := printEndpoint(cfg, ep)
				fmt.Println(line)
				outputLines = append(outputLines, stripANSI(line))
			}
		}
	}

	if cfg.OutPrefix != "" {
		writeMultiStream(cfg, allFound)
	}

	if cfg.OutputFile != "" && len(outputLines) > 0 {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		} else {
			for _, line := range outputLines {
				fmt.Fprintln(f, line)
			}
			f.Close()
			logInfo(cfg, "\n%s[+]%s Saved to %s", cGreen, cReset, cfg.OutputFile)
		}
	}

	logInfo(cfg, "\n%s[*]%s Done. %d new endpoint(s) discovered.", cCyan, cReset, len(allFound))
}

// applyFuzz replaces all {param} placeholders with FUZZ
var rePlaceholder = regexp.MustCompile(`\{[^}]+\}`)

func applyFuzz(u string) string {
	return rePlaceholder.ReplaceAllString(u, "FUZZ")
}

// matchesScope: host == scope atau *.scope
// twoPartPublicSuffix: suffix publik 2-label umum (terutama .id) — bila
// 2-label terakhir cocok, pakai 3 label agar evil.co.id != target.co.id.
var twoPartPublicSuffix = map[string]bool{
	"ac.id": true, "co.id": true, "or.id": true, "go.id": true,
	"mil.id": true, "net.id": true, "web.id": true, "my.id": true,
	"biz.id": true, "ponpes.id": true, "co.uk": true, "org.uk": true,
	"me.uk": true, "ltd.uk": true, "plc.uk": true, "com.au": true,
	"net.au": true, "org.au": true, "co.jp": true, "ne.jp": true,
	"or.jp": true, "co.in": true, "com.br": true, "com.sg": true,
	"co.za": true, "com.my": true,
}

// registrableDomain: aproksimasi cerdas (api.apps.binus.ac.id -> binus.ac.id).
// IP/v6 kembali utuh, port dibuang.
func registrableDomain(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i:], "]") {
		// hati-hati IPv6: hanya strip port berbentuk :angka di akhir
		if _, err := strconv.Atoi(h[i+1:]); err == nil {
			h = h[:i]
		}
	}
	h = strings.Trim(h, "[]")
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
//
// IsBoolFlag agar bentuk bare valid; bentuk spasi (`--scope-exact api.x`)
// TIDAK didukung (api.x akan dianggap URL target) — pakai `=`.
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
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(scope), "*."), "."))
}

// passScopeFilter: default luas (tanpa flag scope -> semua lolos).
// --scope D [+ --scope-exact] dan -bs (union) — lolos bila SALAH SATU cocok.
func passScopeFilter(cfg *Config, absURL, scopeSrcHost string) bool {
	h := extractHost(absURL)
	ex := cfg.ScopeExact
	// 1. --scope-exact=D : tepat host D (single-flag)
	if ex.set && ex.domain != "" {
		if h != "" && h == ex.domain {
			return true
		}
	}
	// 2. bare --scope-exact : exact-kan --scope / -bs (subtree ikut mati)
	if ex.set && ex.domain == "" && ex.modifier {
		if cfg.Scope != "" {
			return h != "" && h == normScopeHost(cfg.Scope)
		}
		if scopeSrcHost != "" {
			return h != "" && h == strings.ToLower(scopeSrcHost)
		}
		// modifier tanpa scope/bs: no-op -> lanjut ke aturan umum
	}
	// 3. subtree --scope D (D + *.D)
	if cfg.Scope != "" && matchesScope(absURL, cfg.Scope) {
		return true
	}
	// 4. -bs : regdom sumber
	if cfg.BaseScope && scopeSrcHost != "" && h != "" {
		rh, rs := registrableDomain(h), registrableDomain(scopeSrcHost)
		if rh != "" && rh == rs {
			return true
		}
	}
	// 5. default luas: tanpa constraint
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
	host := strings.ToLower(u.Hostname())
	scope = strings.ToLower(strings.TrimPrefix(scope, "*."))
	return host == scope || strings.HasSuffix(host, "."+scope)
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

// ─── v3: multi-stream output (pipelineable) ────────────────────────────────────
// One extraction → three purpose-built files:
//
//	<p>.txt      plain AbsURL, one per line  → pipe to httpx/ffuf/nuclei
//	<p>.jsonl    full record per line        → jq / tooling
//	<p>.curl.sh  ready-to-run curl commands  → manual testing
func writeMultiStream(cfg *Config, eps []Endpoint) {
	var urls, jsonls, curls []string
	for _, ep := range eps {
		e := enrichEndpoint(ep)
		u := ep.AbsURL
		if cfg.Fuzz {
			u = e.URL
		}
		urls = append(urls, u)
		b, _ := json.Marshal(Result{
			URL: u, Method: ep.Method, Params: ep.Params,
			Body: e.Body, Interest: ep.Interest, Source: ep.Source,
		})
		jsonls = append(jsonls, string(b))
		curls = append(curls, buildCurl(ep, cfg.BodyFormat)...)
	}
	writeLinesFile(cfg.OutPrefix+".txt", urls)
	writeLinesFile(cfg.OutPrefix+".jsonl", jsonls)
	writeLinesFile(cfg.OutPrefix+".curl.sh", curls)
	logInfo(cfg, "%s[+]%s Multi-stream: %s.txt (%d) · %s.jsonl · %s.curl.sh",
		cGreen, cReset, cfg.OutPrefix, len(urls), cfg.OutPrefix, cfg.OutPrefix)
}

func writeLinesFile(path string, lines []string) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", path, err)
		return
	}
	defer f.Close()
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
}
