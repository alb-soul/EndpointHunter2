package main

// ============================================================
// endpoint-hunter2 — extractor.go (patched)
//
// PERUBAHAN vs v1:
//   * normaliseTemplateURL: regexp.MustCompile di-hoist ke package var
//     (dulu compile tiap panggil → berat di file JS besar).
//   * extractEndpoints: scan seluruh konten SEKALI per pola (bukan per-baris ×
//     per-pola) + lineIndex untuk nomor baris. Ekstraksi param pakai WINDOW
//     KARAKTER di sekitar match (bukan ±3 baris) → memperbaiki blowup pada JS
//     minified (dulu: konteks = seluruh file, di-regex ulang PER match).
// ============================================================

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// ─── Endpoint ─────────────────────────────────────────────────────────────────

type Endpoint struct {
	RawURL   string
	AbsURL   string
	Method   string
	Params   []string
	Source   string
	Line     int
	Interest string
}

// ─── Extraction Patterns ──────────────────────────────────────────────────────

type ExtractionPattern struct {
	Name          string
	Regex         *regexp.Regexp
	URLGroup      int
	MethodGroup   int
	DefaultMethod string
}

var extractionPatterns = []ExtractionPattern{
	{
		Name:          "fetch+method",
		Regex:         regexp.MustCompile(`fetch\s*\(\s*` + bt + `([^` + bte + `\s]+)` + bt + `\s*,\s*\{[^}]*method\s*:\s*['"]([A-Za-z]+)['"]`),
		URLGroup:      1,
		MethodGroup:   2,
		DefaultMethod: "GET",
	},
	{
		Name:          "ofetch/$fetch",
		Regex:         regexp.MustCompile(`\b(?:ofetch|\$fetch)\s*\(\s*` + bt + `([^` + bte + `\s]{4,})` + bt),
		URLGroup:      1,
		DefaultMethod: "GET",
	},
	{
		Name:          "ky",
		Regex:         regexp.MustCompile(`\bky\s*\.\s*(get|post|put|delete|patch|head)\s*\(\s*` + bt + `([^` + bte + `\s]{4,})` + bt),
		URLGroup:      2,
		MethodGroup:   1,
		DefaultMethod: "GET",
	},
	{
		Name:          "fetch",
		Regex:         regexp.MustCompile(`\bfetch\s*\(\s*` + bt + `([^` + bte + `\s]{4,})` + bt),
		URLGroup:      1,
		DefaultMethod: "GET",
	},
	{
		Name:          "axios.method",
		Regex:         regexp.MustCompile(`\baxios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*` + bt + `([^` + bte + `\s]{4,})` + bt),
		URLGroup:      2,
		MethodGroup:   1,
		DefaultMethod: "GET",
	},
	{
		Name:          "axios-config-url-method",
		Regex:         regexp.MustCompile(`\baxios\s*\(\s*\{[^}]{0,200}url\s*:\s*` + bt + `([^` + bte + `\s]{4,})` + bt + `[^}]{0,200}method\s*:\s*['"]([A-Za-z]+)['"]`),
		URLGroup:      1,
		MethodGroup:   2,
		DefaultMethod: "GET",
	},
	{
		Name:          "axios-config-method-url",
		Regex:         regexp.MustCompile(`\baxios\s*\(\s*\{[^}]{0,200}method\s*:\s*['"]([A-Za-z]+)['"]\s*,[^}]{0,200}url\s*:\s*` + bt + `([^` + bte + `\s]{4,})` + bt),
		URLGroup:      2,
		MethodGroup:   1,
		DefaultMethod: "GET",
	},
	{
		Name:          "XHR.open",
		Regex:         regexp.MustCompile(`\.open\s*\(\s*['"]([A-Z]+)['"]\s*,\s*` + bt + `([^` + bte + `\s]{4,})` + bt),
		URLGroup:      2,
		MethodGroup:   1,
		DefaultMethod: "GET",
	},
	{
		Name:          "$.ajax",
		Regex:         regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]{0,300}url\s*:\s*` + bt + `([^` + bte + `\s]{4,})` + bt),
		URLGroup:      1,
		DefaultMethod: "GET",
	},
	{
		Name:          "$.get/post",
		Regex:         regexp.MustCompile(`\$\.(get|post|put|delete)\s*\(\s*` + bt + `([^` + bte + `\s]{4,})` + bt),
		URLGroup:      2,
		MethodGroup:   1,
		DefaultMethod: "GET",
	},
	{
		Name:          "superagent",
		Regex:         regexp.MustCompile(`\brequest\s*\.\s*(get|post|put|delete|patch)\s*\(\s*` + bt + `([^` + bte + `\s]{4,})` + bt),
		URLGroup:      2,
		MethodGroup:   1,
		DefaultMethod: "GET",
	},
	{
		Name:          "router-definition",
		Regex:         regexp.MustCompile(`(?:router|app)\s*\.\s*(get|post|put|delete|patch|all|use)\s*\(\s*` + bt + `([^` + bte + `\s]{2,})` + bt),
		URLGroup:      2,
		MethodGroup:   1,
		DefaultMethod: "GET",
	},
	{
		Name:          "url-var-assignment",
		Regex:         regexp.MustCompile(`(?i)(?:^|[,\s{(])(?:url|endpoint|path|apiPath|apiUrl|baseUrl|actionUrl|href|action)\s*[=:]\s*` + bt + `(\/?(?:https?:\/\/|\/)[^` + bte + `\s<>{}|\\^]{4,})` + bt),
		URLGroup:      1,
		DefaultMethod: "GET",
	},
	{
		Name:          "api-path-literal",
		Regex:         regexp.MustCompile(`['"\x60](\/(?:api|v\d+|internal|admin|auth|rest|graphql|_api|service|backend|private|management|debug|config|webhook|callback|oauth|token|user|account|payment|order|search|upload|download|export|import|report|dashboard|panel|portal|rpc|ws|socket)[\/a-zA-Z0-9_\-\.{}:@!$&()*+,;=%?#]{2,})['"\x60]`),
		URLGroup:      1,
		DefaultMethod: "GET",
	},
	{
		Name:          "absolute-url",
		Regex:         regexp.MustCompile(`['"\x60]((?:https?|wss?)://[a-zA-Z0-9\-\.]+(?::[0-9]+)?\/[^\s'"\x60<>(){}|\\^]{4,})['"\x60]`),
		URLGroup:      1,
		DefaultMethod: "GET",
	},
}

const bt = `['"\x60]`
const bte = `'"\x60`

// ─── Parameter Extraction ─────────────────────────────────────────────────────

var (
	reQueryParam   = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_\-]*)=`)
	rePathParam    = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}|/:([a-zA-Z_][a-zA-Z0-9_]*)`)
	reTemplateVar  = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_\.]*)\}`)
	reBodyParam    = regexp.MustCompile(`(?:body|data|payload|params)\s*[=:]\s*\{([^}]{1,300})\}`)
	reBodyParamKey = regexp.MustCompile(`['"]?([a-zA-Z_][a-zA-Z0-9_]*)['"]?\s*:`)
	// v2: hoisted (dulu di-compile tiap normaliseTemplateURL dipanggil)
	reConcatTail = regexp.MustCompile(`\s*\+\s*\w+\s*$`)
)

func extractParams(rawURL string, contextLines []string) []string {
	seen := make(map[string]bool)
	var params []string

	add := func(p string) {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] && len(p) < 40 {
			seen[p] = true
			params = append(params, p)
		}
	}

	for _, m := range reQueryParam.FindAllStringSubmatch(rawURL, -1) {
		add(m[1])
	}
	for _, m := range rePathParam.FindAllStringSubmatch(rawURL, -1) {
		if m[1] != "" {
			add(m[1])
		} else {
			add(m[2])
		}
	}
	for _, m := range reTemplateVar.FindAllStringSubmatch(rawURL, -1) {
		add(m[1])
	}

	ctx := strings.Join(contextLines, "\n")
	for _, m := range reBodyParam.FindAllStringSubmatch(ctx, -1) {
		for _, km := range reBodyParamKey.FindAllStringSubmatch(m[1], -1) {
			k := km[1]
			if k != "" && k != "true" && k != "false" && k != "null" {
				add(k)
			}
		}
	}
	return params
}

// normaliseTemplateURL converts ${var} → {var} and removes trailing concat noise
func normaliseTemplateURL(raw string) string {
	s := reTemplateVar.ReplaceAllString(raw, `{$1}`)
	s = reConcatTail.ReplaceAllString(s, `/{param}`)
	return s
}

// ─── Interest Scoring ─────────────────────────────────────────────────────────

var highKeywords = []string{
	"admin", "internal", "debug", "dev", "test", "management",
	"hidden", "secret", "private", "config", "backup", "shell",
	"console", "superuser", "root", "system", "manage", "master",
	"monitor", "panel", "portal", "ops", "staff", "backdoor",
}

var mediumKeywords = []string{
	"api", "v1", "v2", "v3", "v4", "auth", "login", "logout",
	"user", "account", "profile", "payment", "order", "session",
	"token", "oauth", "upload", "export", "import", "webhook",
	"graphql", "rest", "rpc", "ws", "socket", "report", "search",
}

func scoreInterest(u string) string {
	lower := strings.ToLower(u)
	for _, kw := range highKeywords {
		if strings.Contains(lower, kw) {
			return "HIGH"
		}
	}
	for _, kw := range mediumKeywords {
		if strings.Contains(lower, kw) {
			return "MED"
		}
	}
	return "LOW"
}

// ─── Static Asset Filter ──────────────────────────────────────────────────────

var staticExtensions = map[string]bool{
	".js": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".otf": true, ".map": true, ".mp4": true,
	".webp": true, ".pdf": true, ".zip": true, ".gz": true,
}

var staticHosts = []string{
	"cdn.", "fonts.googleapis.com", "fonts.gstatic.com", "jquery.com",
	"bootstrapcdn.com", "cdnjs.cloudflare.com", "unpkg.com",
	"jsdelivr.net", "ajax.googleapis.com", "static.", "assets.",
}

func isStaticAsset(rawURL string) bool {
	path := rawURL
	if idx := strings.Index(path, "?"); idx > 0 {
		path = path[:idx]
	}
	for ext := range staticExtensions {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}
	lower := strings.ToLower(rawURL)
	for _, h := range staticHosts {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

// ─── Base URL Auto-Detection ──────────────────────────────────────────────────

var baseURLDeclarations = []*regexp.Regexp{
	regexp.MustCompile(`(?i)axios\s*\.defaults\s*\.baseURL\s*=\s*['"](\s*https?://[^'"]{5,120})\s*['"]`),
	regexp.MustCompile(`(?i)base[_]?[Uu][Rr][Ll]\s*[=:]\s*['"](\s*https?://[^'"]{5,120})\s*['"]`),
	regexp.MustCompile(`(?i)API[_]?BASE(?:[_]?URL)?\s*[=:]\s*['"](\s*https?://[^'"]{5,120})\s*['"]`),
	regexp.MustCompile(`(?i)api[_]?(?:url|endpoint|host|root|server|origin)\s*[=:]\s*['"](\s*https?://[^'"]{5,120})\s*['"]`),
	regexp.MustCompile(`(?i)root[_]?[Uu][Rr][Ll]\s*[=:]\s*['"](\s*https?://[^'"]{5,120})\s*['"]`),
	regexp.MustCompile(`(?i)(?:server|backend|service)[_]?[Uu][Rr][Ll]\s*[=:]\s*['"](\s*https?://[^'"]{5,120})\s*['"]`),
	regexp.MustCompile(`(?i)(?:VUE_APP|REACT_APP|NEXT_PUBLIC|VITE)[_]API[_]?(?:URL|BASE|ENDPOINT)\s*[=:]\s*['"](\s*https?://[^'"]{5,120})\s*['"]`),
	regexp.MustCompile(`process\.env\.\w+\s*\|\|\s*['"](\s*https?://[^'"]{5,120})\s*['"]`),
	regexp.MustCompile(`(?i)(?:^|[,\s{(])(?:host|origin|domain|endpoint)\s*[=:]\s*['"](\s*https?://[^'"]{5,120})\s*['"]`),
}

var noisyHosts = []string{
	"cdn.", "fonts.googleapis", "fonts.gstatic", "cdnjs.", "unpkg.",
	"jsdelivr.", "ajax.googleapis", "sentry.io", "segment.io",
	"analytics", "tracking", "doubleclick", "google-analytics",
	"stripe.com", "paypal.com", "facebook.com", "twitter.com",
	"amazonaws.com", "cloudfront.net", "fastly.net", "akamai",
}

func isNoisyHost(host string) bool {
	lower := strings.ToLower(host)
	for _, n := range noisyHosts {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

var reAbsoluteURL = regexp.MustCompile(`https?://([a-zA-Z0-9\-\.]+(?::[0-9]+)?)(?:/[^\s'"` + "`" + `<>(){}|\\^]*)`)

// pageLikeExtensions: URL halaman frontend / aset — tidak pernah valid
// sebagai API base.
// BUGFIX binus-2026-09: deklarasi MoreServiceUrl="https://host/LoginAD.php"
// sempat jadi effectiveBase (lengkap dgn path); filter external lalu membuang
// URL API absolut di sibling subdomain (api.apps.binus.ac.id). Kandidat
// begini di-skip agar deteksi jatuh ke majority-vote / origin.
var pageLikeExtensions = []string{
	".php", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx", ".do", ".action",
	".html", ".htm", ".xhtml", ".js", ".jsx", ".ts", ".css", ".less", ".scss",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
}

func isPageLikeURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return false
	}
	last := u.Path
	if i := strings.LastIndex(last, "/"); i >= 0 {
		last = last[i+1:]
	}
	if i := strings.IndexAny(last, "?#"); i >= 0 {
		last = last[:i]
	}
	dot := strings.LastIndex(last, ".")
	if dot <= 0 || dot == len(last)-1 {
		return false
	}
	ext := strings.ToLower(last[dot:])
	for _, e := range pageLikeExtensions {
		if ext == e {
			return true
		}
	}
	return false
}

func detectBaseURL(content, jsURL string) string {
	for _, pat := range baseURLDeclarations {
		if m := pat.FindStringSubmatch(content); len(m) > 1 {
			candidate := strings.TrimSpace(m[1])
			candidate = strings.TrimRight(candidate, "/")
			if candidate == "" || isNoisyHost(extractHost(candidate)) {
				continue
			}
			if isPageLikeURL(candidate) {
				continue // URL halaman frontend — bukan API base
			}
			return candidate
		}
	}

	// Absolute URLs must NOT hijack the base on weak signal: require >=3
	// DISTINCT absolute URLs to a host and score >= 5 (distinct +2 bonus
	// if any has API path). 1-2 stray absolute links (docs, examples)
	// keep page-origin resolution. Hosts iterated sorted for determinism.
	seenURLs := make(map[string]map[string]bool)
	hostScheme := make(map[string]string)
	hostHasAPI := make(map[string]bool)
	for _, m := range reAbsoluteURL.FindAllStringSubmatch(content, -1) {
		host := strings.ToLower(m[1])
		if isNoisyHost(host) {
			continue
		}
		fullURL := m[0]
		if seenURLs[host] == nil {
			seenURLs[host] = make(map[string]bool)
		}
		seenURLs[host][fullURL] = true
		lower := strings.ToLower(fullURL)
		if strings.Contains(lower, "/api") ||
			strings.Contains(lower, "/v1") ||
			strings.Contains(lower, "/v2") ||
			strings.Contains(lower, "/v3") ||
			strings.Contains(lower, "/auth") ||
			strings.Contains(lower, "/graphql") ||
			strings.Contains(lower, "/rest") ||
			strings.Contains(lower, "/rpc") {
			hostHasAPI[host] = true
		}
		if strings.HasPrefix(fullURL, "https://") {
			hostScheme[host] = "https"
		} else if _, ok := hostScheme[host]; !ok {
			hostScheme[host] = "http"
		}
	}

	var hosts []string
	for host := range seenURLs {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	var bestHost string
	var bestScore int
	for _, host := range hosts {
		score := len(seenURLs[host])
		if hostHasAPI[host] {
			score += 2
		}
		if score > bestScore && len(seenURLs[host]) >= 3 && score >= 5 {
			bestScore = score
			bestHost = host
		}
	}
	if bestHost != "" {
		scheme := hostScheme[bestHost]
		if scheme == "" {
			scheme = "https"
		}
		return scheme + "://" + bestHost
	}

	return originOf(jsURL)
}

func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// ─── URL Resolver ─────────────────────────────────────────────────────────────

func resolveURL(raw, jsURL, baseOverride string) string {
	raw = strings.TrimSpace(raw)
	raw = normaliseTemplateURL(raw)

	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if strings.HasPrefix(raw, "//") {
		scheme := "https"
		base := baseOverride
		if base == "" {
			base = jsURL
		}
		if bu, err := url.Parse(base); err == nil && bu.Scheme != "" {
			scheme = bu.Scheme
		}
		return scheme + ":" + raw
	}

	base := baseOverride
	if base == "" {
		base = jsURL
	}
	baseU, err := url.Parse(base)
	if err != nil || baseU.Host == "" {
		return raw
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	resolved := baseU.ResolveReference(ref)
	result := resolved.String()
	result = strings.ReplaceAll(result, "%7B", "{")
	result = strings.ReplaceAll(result, "%7D", "}")
	return result
}

// ─── Known URL Normalisation ──────────────────────────────────────────────────

func normaliseForFilter(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(strings.TrimRight(rawURL, "/"))
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		p = "/"
	}
	result := strings.ToLower(u.Hostname()) + p
	return result
}

// ─── lineIndex (v2) ────────────────────────────────────────────────────────────

type lineIndex struct{ starts []int }

func buildLineIndex(content string) *lineIndex {
	starts := []int{0}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &lineIndex{starts: starts}
}

func (li *lineIndex) lineAt(pos int) int {
	lo, hi := 0, len(li.starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if li.starts[mid] <= pos {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1
}

// validHTTPMethod: only real verbs pass; router "USE"/"ALL" etc fall back to DefaultMethod.
func validHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// ─── Core Extractor (v2: whole-content scan + char-window context) ─────────────

const ctxWindow = 500 // char di kiri/kanan match untuk ekstraksi param

// reVarAssign: `NAME="https://..."` / `NAME:'...'` / `NAME:...` — deklarasi
// URL absolut ke variabel/properti. Value wajib absolut (presisi tinggi).
// BUGFIX binus-2026-09: endpoint hasil deklarasi bare-string selalu
// berlabel DefaultMethod (GET) walau call-site memakai POST.
var reVarAssign = regexp.MustCompile(`[\s,{(;]([A-Za-z_$][A-Za-z0-9_$]{0,63})\s*[=:]\s*["'](https?://[^'"` + "`" + `\s<>(){}|\\^]+)["']`)

// collectVarURLs: namaVar(lower) -> URL absolut (first wins).
func collectVarURLs(content string) map[string]string {
	out := map[string]string{}
	for _, m := range reVarAssign.FindAllStringSubmatch(content, -1) {
		if len(m) < 3 {
			continue
		}
		k := strings.ToLower(m[1])
		if _, ok := out[k]; !ok {
			out[k] = m[2]
		}
	}
	return out
}

// resolveVarCallMethods: hubungkan call-site fetch(VAR,...)/axios -> method
// eksplisit. absURL(lower) -> METHOD. Prefer non-GET saat konflik.
func resolveVarCallMethods(content string, varURLs map[string]string) map[string]string {
	out := map[string]string{}
	if len(varURLs) == 0 {
		return out
	}
	put := func(varName, method string) {
		u, ok := varURLs[strings.ToLower(varName)]
		if !ok || u == "" {
			return
		}
		method = strings.ToUpper(method)
		if !validHTTPMethod(method) {
			return
		}
		k := strings.ToLower(u)
		if cur, dup := out[k]; !dup || (cur == "GET" && method != "GET") {
			out[k] = method
		}
	}
	// fetch(VAR, {method:"POST",...}) — options chunk dibatasi, method
	// biasanya mendahului nested headers:{...}
	for _, m := range regexp.MustCompile(`fetch\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*\{[^}]{0,400}method\s*:\s*['"]([A-Za-z]+)['"]`).FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			put(m[1], m[2])
		}
	}
	// axios.get|post|...(VAR)
	for _, m := range regexp.MustCompile(`axios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)`).FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			put(m[2], m[1])
		}
	}
	// axios({url:VAR, method:"POST"}) & urutan terbalik
	for _, m := range regexp.MustCompile(`axios\s*\(\s*\{[^}]{0,300}url\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)[^}]{0,300}method\s*:\s*['"]([A-Za-z]+)['"]`).FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			put(m[1], m[2])
		}
	}
	for _, m := range regexp.MustCompile(`axios\s*\(\s*\{[^}]{0,300}method\s*:\s*['"]([A-Za-z]+)['"]\s*,[^}]{0,300}url\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)`).FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			put(m[2], m[1])
		}
	}
	// $.ajax({url:VAR, method/type:"POST"})
	for _, m := range regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]{0,300}url\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)[^}]{0,300}(?:method|type)\s*:\s*['"]([A-Za-z]+)['"]`).FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			put(m[1], m[2])
		}
	}
	// $.get|post(VAR)
	for _, m := range regexp.MustCompile(`\$\.(get|post)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)`).FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			put(m[2], m[1])
		}
	}
	// xhr.open("POST", VAR)
	for _, m := range regexp.MustCompile(`\.open\s*\(\s*['"]([A-Za-z]+)['"]\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)`).FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			put(m[2], m[1])
		}
	}
	return out
}

func extractEndpoints(content, sourceURL, jsURL, baseOverride string, includeAssets, includeExternal bool) ([]Endpoint, string, int) {
	var results []Endpoint
	seen := make(map[string]bool)
	skippedExternal := map[string]bool{}

	effectiveBase := baseOverride
	if effectiveBase == "" {
		effectiveBase = detectBaseURL(content, jsURL)
	}

	// Atribusi method dari call-site variabel (override label default).
	varMethods := resolveVarCallMethods(content, collectVarURLs(content))

	li := buildLineIndex(content)
	n := len(content)

	for _, pat := range extractionPatterns {
		for _, loc := range pat.Regex.FindAllStringSubmatchIndex(content, -1) {
			if len(loc) < (pat.URLGroup+1)*2 {
				continue
			}
			s, e := loc[pat.URLGroup*2], loc[pat.URLGroup*2+1]
			if s < 0 || e < 0 {
				continue
			}
			rawURL := strings.TrimSpace(content[s:e])
			if len(rawURL) < 4 {
				continue
			}
			if strings.Contains(rawURL, " ") {
				continue
			}
			if strings.Contains(rawURL, "\\") || strings.HasPrefix(rawURL, "#") {
				continue
			}

			rawURL = normaliseTemplateURL(rawURL)
			absURL := resolveURL(rawURL, jsURL, effectiveBase)

			if !includeAssets && isStaticAsset(absURL) {
				continue
			}
			if !includeExternal {
				baseHost := extractHost(effectiveBase)
				absHost := extractHost(absURL)
				if !sameSite(baseHost, absHost) {
					skippedExternal[strings.ToLower(absURL)] = true
					continue
				}
			}

			dk := dedupKey(absURL)
			if seen[dk] {
				continue
			}
			seen[dk] = true

			method := strings.ToUpper(pat.DefaultMethod)
			if pat.MethodGroup > 0 && len(loc) >= (pat.MethodGroup+1)*2 {
				ms, me := loc[pat.MethodGroup*2], loc[pat.MethodGroup*2+1]
				if ms >= 0 && me >= 0 {
					method = strings.ToUpper(content[ms:me])
				}
			}
			if !validHTTPMethod(method) {
				method = strings.ToUpper(pat.DefaultMethod)
			}
			// Override hanya bila situs literal tak memberi info eksplisit
			// (method == DefaultMethod): call-site variabel lebih tahu.
			if method == strings.ToUpper(pat.DefaultMethod) {
				if vm, ok := varMethods[strings.ToLower(absURL)]; ok && validHTTPMethod(vm) {
					method = vm
				}
			}

			// v2: konteks = window karakter di sekitar match (bukan ±3 baris).
			// Mencegah blowup pada JS minified (dulu konteks = seluruh file per match).
			cs := s - ctxWindow
			if cs < 0 {
				cs = 0
			}
			ce := e + ctxWindow
			if ce > n {
				ce = n
			}
			params := extractParams(rawURL, []string{content[cs:ce]})

			lineNum := li.lineAt(s)
			results = append(results, Endpoint{
				RawURL:   rawURL,
				AbsURL:   absURL,
				Method:   method,
				Params:   params,
				Source:   fmt.Sprintf("%s:%d", sourceURL, lineNum),
				Line:     lineNum,
				Interest: scoreInterest(absURL),
			})
		}
	}
	return results, effectiveBase, len(skippedExternal)
}

func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// dedupKey: canonical key that preserves case-sensitive path/query
// (only scheme+host are lowercased). /API/Users != /api/users.
func dedupKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return strings.ToLower(rawURL)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

// sameSite: exact host match or subdomain-of-base (no naive SLD —
// evil.co.uk must NOT equal example.co.uk).
func sameSite(baseHost, absHost string) bool {
	if baseHost == "" || absHost == "" {
		return true
	}
	if absHost == baseHost {
		return true
	}
	return strings.HasSuffix(absHost, "."+baseHost)
}

// sameSLD kept for compat (unused by filter logic).
func sameSLD(a, b string) bool {
	return sameSite(a, b)
}
