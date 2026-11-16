package main

// ============================================================
// endpoint-hunter2 — extractor.go
//
//   * Pra-ekstraksi (normalize.go): decode escape/entity aman, join literal,
//     propagasi konstanta LINEAR, rekonstruksi route ("/a/"+id, .concat(),
//     `${x}`) — dengan peta posisi agar source "file:line:col" akurat.
//   * Pola (patterns.go) dicari lewat anchor literal + regex ter-anchor.
//   * Resolusi URL per jenis temuan:
//       - HTML           : base dokumen (<base href> atau URL halaman)
//       - instance/axios : baseURL deklarasi (join path ala axios)
//       - route/navigasi : origin halaman
//       - relatif di JS  : origin aplikasi (fetch relatif ke DOKUMEN, bukan ke
//                          lokasi file JS); ditandai PageRel agar bisa
//                          ditempel ulang ke origin halaman yang memuat JS bila
//                          JS di-host di CDN (lihat main.go reattribute).
//   * Method & params dari argumen panggilan / objek config yang memuat URL
//     (context.go), bukan jendela ±500 char (dulu bocor ke panggilan tetangga).
// ============================================================

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// ─── Endpoint ─────────────────────────────────────────────────────────────────

type Endpoint struct {
	RawURL   string
	AbsURL   string
	Method   string
	Params   []string // gabungan semua param (kompat: field "params" jsonl)
	Source   string   // "<url-sumber>:<line>:<col>"
	Line     int
	Col      int
	Interest string

	MethodExplicit bool     // method berasal dari kode (bukan default GET)
	QueryParams    []string // kunci yang pasti query (axios params:, $.get GET)
	BodyKeys       []string // kunci body (body:/data:/json:, data axios.post)
	PageRel        bool     // relatif-origin dari JS/JSON (kandidat atribusi ulang)
	RelPath        string   // path relatif ternormalisasi (diawali "/")
	PageURL        string   // URL record sumber

	seq, pos int
}

// key url-var yang berarti navigasi/route halaman (bukan endpoint API)
var routeKeys = map[string]bool{"path": true, "href": true, "action": true, "to": true, "redirectto": true, "redirecturl": true, "redirect": true, "link": true}

var (
	reTemplateVar = regexp.MustCompile(`\$\{([^{}]+)\}`)
	reQueryParam  = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_\-\[\]]*)=`)
	rePathParam   = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}|/:([a-zA-Z_][a-zA-Z0-9_]*)`)
	reNextDynSeg  = regexp.MustCompile(`/\[\[?(?:\.\.\.)?([A-Za-z_][A-Za-z0-9_]*)\]\]?`)
	reSchemeEP    = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*:`)
	reMimeLike    = regexp.MustCompile(`^(?:application|text|image|audio|video|font|multipart|model|message)/[A-Za-z0-9.+\-]+$`)
	reBaseHref    = regexp.MustCompile(`(?i)<base\b[^>]*?\bhref\s*=\s*["']([^"']+)["']`)
	reScriptSrc   = regexp.MustCompile(`(?i)<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']`)
	reFormTag     = regexp.MustCompile(`(?i)<form\b([^>]{0,800})>`)
	reFormAction  = regexp.MustCompile(`(?i)\baction\s*=\s*["']([^"']*)["']`)
	reFormMethod  = regexp.MustCompile(`(?i)\bmethod\s*=\s*["']?([A-Za-z]+)`)
)

func urlParams(rawURL string) []string {
	var out []string
	for _, m := range reQueryParam.FindAllStringSubmatch(rawURL, -1) {
		out = append(out, m[1])
	}
	for _, m := range rePathParam.FindAllStringSubmatch(rawURL, -1) {
		if m[1] != "" {
			out = append(out, m[1])
		} else {
			out = append(out, m[2])
		}
	}
	return out
}

// normaliseTemplateURL: ${a.id} -> {id}; "{BASE}/x" -> "/x"; Next.js /[id] -> /{id}.
func normaliseTemplateURL(raw string) string {
	s := raw
	if strings.Contains(s, "${") {
		s = reTemplateVar.ReplaceAllStringFunc(s, func(m string) string {
			return "{" + lastIdent(m[2:len(m)-1]) + "}"
		})
	}
	s = dropLeadingPlaceholder(s)
	if strings.Contains(s, "/[") {
		s = reNextDynSeg.ReplaceAllString(s, "/{$1}")
	}
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

// urlTokens: kata dari URL (pisah non-alnum + camelCase), lowercase.
// Dulu substring mentah: "dev" cocok "devices", "test" cocok "latest",
// "ws" cocok "news", "rest" cocok "interest" -> skor HIGH/MED palsu.
func urlTokens(u string) []string {
	var toks []string
	cur := make([]byte, 0, 32)
	flush := func() {
		if len(cur) > 0 {
			toks = append(toks, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		isAl := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAl {
			flush()
			continue
		}
		if c >= 'A' && c <= 'Z' && i > 0 && u[i-1] >= 'a' && u[i-1] <= 'z' {
			flush()
		}
		cur = append(cur, c)
	}
	flush()
	return toks
}

func kwHit(tok, kw string) bool {
	if !strings.HasPrefix(tok, kw) {
		return false
	}
	return len(tok) == len(kw) || (len(tok) == len(kw)+1 && tok[len(kw)] == 's') || len(kw) >= 5
}

func scoreInterest(u string) string {
	toks := urlTokens(u)
	for _, t := range toks {
		for _, kw := range highKeywords {
			if kwHit(t, kw) {
				return "HIGH"
			}
		}
	}
	for _, t := range toks {
		for _, kw := range mediumKeywords {
			if kwHit(t, kw) {
				return "MED"
			}
		}
	}
	return "LOW"
}

// ─── Static Asset Filter ──────────────────────────────────────────────────────

var staticExtensions = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".otf": true, ".map": true, ".mp4": true, ".webm": true,
	".webp": true, ".avif": true, ".pdf": true, ".zip": true, ".gz": true, ".mp3": true,
}

// host aset murni (cocok penuh / subdomain-nya)
var staticHostSuffixes = []string{
	"fonts.googleapis.com", "fonts.gstatic.com", "jquery.com",
	"bootstrapcdn.com", "cdnjs.cloudflare.com", "unpkg.com", "jsdelivr.net",
	"ajax.googleapis.com",
}

// label host pertama yang menandai host aset (cdn.x / static.x / assets.x)
var staticHostLabels = []string{"cdn", "static", "assets"}

func isStaticExt(rawURL string) bool {
	p := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		p = u.Path
	} else if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return staticExtensions[strings.ToLower(path.Ext(p))]
}

func isStaticHost(host string) bool {
	host = strings.ToLower(host)
	for _, h := range staticHostSuffixes {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	first := host
	if i := strings.IndexByte(host, '.'); i > 0 {
		first = host[:i]
	}
	for _, l := range staticHostLabels {
		if first == l {
			return true
		}
	}
	return false
}

// isStaticAsset: ekstensi aset pada PATH, atau host aset. Dulu substring di
// SELURUH URL: "/api/assets.list" atau "?ref=static.x" ikut terbuang (FN).
func isStaticAsset(rawURL string) bool {
	return isStaticExt(rawURL) || isStaticHost(extractHost(rawURL))
}

// ─── Base URL Auto-Detection ──────────────────────────────────────────────────

const baseVal = `\s*((?:https?://[^'"\s]{3,120})|/[A-Za-z0-9_\-./]{1,80})\s*`
const baseAbs = `\s*(https?://[^'"\s]{3,120})\s*`

type declPat struct {
	re      *regexp.Regexp // ter-anchor ^
	anchors []string       // lowercase
	pre     func(string, int) bool
	maxLen  int
}

func dp(src string, maxLen int, pre func(string, int) bool, anchors ...string) declPat {
	return declPat{regexp.MustCompile(`^(?:` + src + `)`), anchors, pre, maxLen}
}

// Deklarasi base eksplisit. ['"]? setelah nama key: kunci JSON ("apiUrl": "...")
// juga cocok (dulu tidak).
var baseDecls = []declPat{
	dp(`(?i)axios\s*\.\s*defaults\s*\.\s*baseURL\s*=\s*['"]`+baseVal+`['"]`, 300, nil, "axios"),
	dp(`(?i)axios\s*\.\s*create\s*\(\s*\{[^}]{0,200}?baseURL['"]?\s*:\s*['"]`+baseVal+`['"]`, 500, nil, "axios"),
	dp(`(?i)base[_]?url['"]?\s*[=:]\s*['"]`+baseVal+`['"]`, 300, nil, "baseurl", "base_url"),
	dp(`(?i)API[_]?BASE(?:[_]?URL)?['"]?\s*[=:]\s*['"]`+baseVal+`['"]`, 300, nil, "api_base", "apibase"),
	dp(`(?i)api[_]?(?:url|endpoint|host|root|server|origin)['"]?\s*[=:]\s*['"]`+baseAbs+`['"]`, 300, nil,
		"api_url", "apiurl", "api_endpoint", "apiendpoint", "api_host", "apihost", "api_root", "apiroot",
		"api_server", "apiserver", "api_origin", "apiorigin"),
	dp(`(?i)root[_]?url['"]?\s*[=:]\s*['"]`+baseAbs+`['"]`, 300, nil, "root_url", "rooturl"),
	dp(`(?i)(?:server|backend|service)[_]?url['"]?\s*[=:]\s*['"]`+baseAbs+`['"]`, 300, nil,
		"server_url", "serverurl", "backend_url", "backendurl", "service_url", "serviceurl"),
	dp(`(?i)(?:VUE_APP|REACT_APP|NEXT_PUBLIC|VITE)(?:_PUBLIC)?_?(?:API_?BASE_?URL|API_?URL|API_?BASE|API_?ENDPOINT|BACKEND_?URL)['"]?\s*[=:]\s*['"]`+baseAbs+`['"]`, 300, nil,
		"vue_app", "react_app", "next_public", "vite"),
	dp(`process\.env\.\w+\s*\|\|\s*['"]`+baseAbs+`['"]`, 300, nil, "process.env"),
	dp(`(?i)(?:host|origin|domain|endpoint)['"]?\s*[=:]\s*['"]`+baseAbs+`['"]`, 300, keyBoundary,
		"host", "origin", "domain", "endpoint"),
}

var noisyHosts = []string{
	"cdn.", "fonts.googleapis", "fonts.gstatic", "cdnjs.", "unpkg.",
	"jsdelivr.", "ajax.googleapis", "sentry.io", "segment.io",
	"analytics", "tracking", "doubleclick", "google-analytics",
	"stripe.com", "paypal.com", "facebook.com", "twitter.com",
	"amazonaws.com", "cloudfront.net", "fastly.net", "akamai",
	"w3.org", "schemas.", "xmlsoap.org", "openxmlformats.org",
	// host dev/contoh tidak pernah jadi base aplikasi (bundle sering memuat
	// sisa "http://localhost:80/..." -> dulu semua path ditempel ke localhost)
	"localhost", "127.0.0.1", "0.0.0.0", "example.org", "example.net",
	// situs pihak ketiga yang sering ditautkan berulang di bundle
	"github.com", "githubusercontent.com", "gitlab.com", "google.com", "gstatic.com",
	"youtube.com", "instagram.com", "linkedin.com", "pinterest.com", "wikipedia.org",
	"mozilla.org", "npmjs.", "momentjs.com", "apple.com", "microsoft.com", "atlassian.net",
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
// sebagai API base (binus-2026-09: MoreServiceUrl=".../LoginAD.php").
var pageLikeExtensions = map[string]bool{
	".php": true, ".aspx": true, ".ashx": true, ".asmx": true, ".jsp": true, ".jspx": true,
	".do": true, ".action": true, ".html": true, ".htm": true, ".xhtml": true, ".js": true,
	".jsx": true, ".ts": true, ".css": true, ".less": true, ".scss": true, ".png": true,
	".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
}

func isPageLikeURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return false
	}
	return pageLikeExtensions[strings.ToLower(path.Ext(u.Path))]
}

type baseCand struct {
	pos int
	url string
}

// detectDeclaredBase: deklarasi base eksplisit. Semua kandidat dikumpulkan
// lalu dipilih: dgn scope -> kandidat in-scope pertama (SDK pihak ketiga
// dgn baseURL sendiri TIDAK lagi membajak path relatif aplikasi); tanpa scope
// -> utamakan registrable domain sama dgn halaman, else kandidat pertama.
func detectDeclaredBase(content, lower, pageURL string, inScope func(string) bool) string {
	var cands []baseCand
	pageOrigin := originOf(pageURL)
	for _, d := range baseDecls {
		starts := anchorStarts(lower, d.anchors, func(p int) int { return p })
		for _, m := range anchoredFind(content, d.re, starts, d.maxLen, d.pre) {
			v := strings.TrimRight(strings.TrimSpace(content[m[2]:m[3]]), "/")
			if v == "" {
				continue
			}
			if strings.HasPrefix(v, "/") {
				if pageOrigin == "" || !apiShapedEP(v+"/") {
					continue // base relatif hanya bila beraroma API (/api, /v1, ...)
				}
				v = pageOrigin + v
			}
			h := extractHost(v)
			if h == "" || isNoisyHost(h) || isPageLikeURL(v) {
				continue
			}
			cands = append(cands, baseCand{m[0], v})
		}
	}
	if len(cands) == 0 {
		return ""
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].pos < cands[j].pos })
	if inScope != nil {
		for _, c := range cands {
			if inScope(extractHost(c.url)) {
				return c.url
			}
		}
		return ""
	}
	if ph := extractHost(pageURL); ph != "" {
		rp := registrableDomain(ph)
		for _, c := range cands {
			if registrableDomain(extractHost(c.url)) == rp {
				return c.url
			}
		}
	}
	return cands[0].url
}

// detectElectedBase: voting URL absolut — butuh >=3 URL BERBEDA ke satu host
// dan skor >=5 (+2 bila ada path API). Host di-iterasi terurut (deterministik).
func detectElectedBase(content string, inScope func(string) bool) string {
	if !strings.Contains(content, "://") {
		return ""
	}
	seenURLs := make(map[string]map[string]bool)
	hostScheme := make(map[string]string)
	hostHasAPI := make(map[string]bool)
	for _, m := range reAbsoluteURL.FindAllStringSubmatch(content, -1) {
		host := strings.ToLower(m[1])
		if isNoisyHost(host) {
			continue
		}
		if inScope != nil && !inScope(strings.Split(host, ":")[0]) {
			continue
		}
		fullURL := m[0]
		if seenURLs[host] == nil {
			seenURLs[host] = make(map[string]bool)
		}
		seenURLs[host][fullURL] = true
		if apiShapedEP(fullURL) {
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
		// wajib ada path API: link dokumentasi/sosmed berulang bukan base API
		if hostHasAPI[host] && score > bestScore && len(seenURLs[host]) >= 3 && score >= 5 {
			bestScore = score
			bestHost = host
		}
	}
	if bestHost == "" {
		return ""
	}
	return hostScheme[bestHost] + "://" + bestHost
}

// detectBaseURL (kompat): base efektif sebuah konten JS.
func detectBaseURL(content, jsURL string) string {
	if b := detectDeclaredBase(content, asciiLower(content), jsURL, nil); b != "" {
		return b
	}
	if b := detectElectedBase(content, nil); b != "" {
		return b
	}
	return originOf(jsURL)
}

func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host
}

// ─── URL Resolver ─────────────────────────────────────────────────────────────

// apiShapedEP: relatif beraroma API.
func apiShapedEP(raw string) bool {
	l := strings.ToLower(raw)
	for _, k := range []string{"/api/", "/api?", "/v1", "/v2", "/v3", "/v4",
		"/graphql", "/rest", "/rpc", "/auth", "/oauth", "/token", "/webhook"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return strings.HasSuffix(l, "/api")
}

func fixBraces(s string) string {
	if strings.Contains(s, "%7") || strings.Contains(s, "%5") {
		s = strings.NewReplacer("%7B", "{", "%7D", "}", "%7b", "{", "%7d", "}", "%5B", "[", "%5D", "]").Replace(s)
	}
	return s
}

// resolveAgainst: resolusi RFC 3986 (semantik browser).
func resolveAgainst(base, raw string) string {
	bu, err := url.Parse(base)
	if err != nil || bu.Host == "" {
		return raw
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return fixBraces(bu.ResolveReference(ref).String())
}

// cleanAbs: validasi URL absolut + bersihkan dot-segment (/a/../b).
func cleanAbs(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || strings.ContainsAny(u.Host, "{}$") {
		return ""
	}
	if strings.Contains(u.Path, "/.") {
		ref := *u
		ref.Scheme, ref.Host, ref.User = "", "", nil
		base := &url.URL{Scheme: u.Scheme, Host: u.Host, User: u.User}
		return fixBraces(base.ResolveReference(&ref).String())
	}
	return raw
}

// rootify: path relatif di JS -> relatif root dokumen ("./a", "../a", "a" -> "/a").
func rootify(raw string) string {
	if strings.HasPrefix(raw, "/") {
		return raw
	}
	for {
		switch {
		case strings.HasPrefix(raw, "./"):
			raw = raw[2:]
		case strings.HasPrefix(raw, "../"):
			raw = raw[3:]
		default:
			return "/" + raw
		}
	}
}

// joinBase: semantik axios (baseURL + url) untuk base deklarasi ber-path API.
// Path yang sudah memuat prefix base (/api/...) ditempel ke origin saja.
func joinBase(base, raw string) string {
	bu, err := url.Parse(base)
	if err != nil || bu.Host == "" {
		return resolveAgainst(base, rootify(raw))
	}
	origin := bu.Scheme + "://" + bu.Host
	bp := strings.TrimRight(bu.Path, "/")
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
		return resolveAgainst(origin+bp+"/", raw)
	}
	r := rootify(raw)
	if bp == "" || !apiShapedEP(bp+"/") {
		return resolveAgainst(origin, r)
	}
	first := bp
	if i := strings.IndexByte(bp[1:], '/'); i >= 0 {
		first = bp[:i+1]
	}
	if r == bp || r == first || strings.HasPrefix(r, bp+"/") || strings.HasPrefix(r, first+"/") || strings.Contains(r, bp+"/") {
		return resolveAgainst(origin, r)
	}
	return resolveAgainst(origin, bp+r)
}

// resolveURL (kompat): resolusi sederhana raw terhadap base/jsURL.
func resolveURL(raw, jsURL, baseOverride string) string {
	raw = normaliseTemplateURL(strings.TrimSpace(raw))
	if reSchemeEP.MatchString(raw) {
		return cleanAbs(raw)
	}
	base := baseOverride
	if base == "" {
		base = jsURL
	}
	if strings.HasPrefix(raw, "//") {
		scheme := "https"
		if bu, err := url.Parse(base); err == nil && bu.Scheme != "" {
			scheme = bu.Scheme
		}
		return scheme + ":" + raw
	}
	return resolveAgainst(base, raw)
}

// ─── Validasi kandidat ───────────────────────────────────────────────────────

var sysPathPrefixes = []string{"/usr/", "/etc/", "/var/", "/opt/", "/bin/", "/sbin/", "/tmp/", "/dev/", "/proc/", "/sys/", "/lib/", "/home/", "/root/", "/mnt/", "/data/", "/private/var/", "/Users/", "/node_modules/", "/webpack/"}

// randomSeg: segmen acak bundle minified (hash/base64): >=16 char,
// huruf besar+kecil+digit, tanpa pemisah.
func randomSeg(seg string) bool {
	if len(seg) < 16 || strings.ContainsAny(seg, "-_.~{}:") {
		return false
	}
	var up, lo, dg bool
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= '0' && c <= '9':
			dg = true
		}
	}
	return up && lo && dg
}

// literalSegment: minimal satu segmen path berisi nama (bukan cuma {x}/:x/angka).
func literalSegment(p string) bool {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || strings.HasPrefix(seg, "{") || strings.HasPrefix(seg, ":") || strings.HasPrefix(seg, "[") {
			continue
		}
		if hasLetter(seg) {
			return true
		}
	}
	return false
}

// validGenericPathEP: saringan FP utk literal generik ("/..." apa saja).
func validGenericPathEP(raw string) bool {
	for _, p := range sysPathPrefixes {
		if strings.HasPrefix(raw, p) {
			return false
		}
	}
	if strings.HasPrefix(raw, "//") && !strings.Contains(raw[2:], "/") {
		return false
	}
	if !literalSegment(raw) {
		return false // tanggal "/2024/01/02", versi, "/{e}"
	}
	p := raw
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	for _, seg := range strings.Split(p, "/") {
		if randomSeg(seg) {
			return false
		}
	}
	// regex / glob literal: "/^\/api/", "/.*", "/**/*.js"
	if strings.ContainsAny(raw, "^|") || strings.Contains(raw, ".*") || strings.Contains(raw, "**") {
		return false
	}
	// karakter kode di bagian PATH ("/},{begin:/", "/a,b(c)") — placeholder
	// {name} dan :param* tetap boleh
	pp := rePlaceholderSeg.ReplaceAllString(p, "")
	pp = strings.ReplaceAll(pp, "*", "")          // :path*
	if strings.ContainsAny(pp, ",{}();!'\"<>`") { // $ boleh: OData /$batch
		return false
	}
	return true
}

var (
	rePlaceholderSeg = regexp.MustCompile(`\{[A-Za-z_][A-Za-z0-9_]*\}`)
	reRegexFlagsTail = regexp.MustCompile(`^/[^/]+(?:/[^/]*)*/(?:[dgimsuy]{1,6}|[dgimsuy]{0,6}\.(?:test|exec|source|flags))$`)
)

// validBarePath: path tanpa quote (prosa/komentar). Tolak bentuk regex
// literal /Android/i, /a/gim, /%20/g (umum di bundle minified).
func validBarePath(raw string) bool {
	if reRegexFlagsTail.MatchString(raw) {
		return false
	}
	return validGenericPathEP(raw)
}

// validPathOrURL: wajib path/URL (mengandung '/').
func validPathOrURL(raw string) bool {
	return strings.Contains(raw, "/") && validLooseRelative(raw)
}

// validLooseRelative: relatif tanpa slash boleh, tapi bukan MIME, header,
// kata ber-spasi, atau tanpa huruf.
func validLooseRelative(raw string) bool {
	if !hasLetter(raw) || reMimeLike.MatchString(raw) {
		return false
	}
	if !strings.Contains(raw, "/") {
		// "Content-Type", "cache-key:1"? kata tunggal hanya bila lowercase path-ish
		for i := 0; i < len(raw); i++ {
			if raw[i] >= 'A' && raw[i] <= 'Z' {
				return false
			}
		}
		if strings.ContainsAny(raw, ":;,=") {
			return false
		}
	}
	return true
}

// validCandidate: saringan umum utk semua pola (setelah normalisasi template).
func validCandidate(raw string, kind patKind) bool {
	if raw == "" || strings.ContainsAny(raw, " \\\t\n") || strings.HasPrefix(raw, "#") {
		return false
	}
	if reSchemeEP.MatchString(raw) || strings.HasPrefix(raw, "//") {
		return true // skema dicek saat resolusi
	}
	if !literalSegment(raw) {
		return false
	}
	if !strings.HasPrefix(raw, "/") && kind != kHTML && kind != kModule {
		// relatif tanpa slash: tolak MIME/tanggal/versi/kunci i18n
		if reMimeLike.MatchString(raw) || !hasLetter(raw) {
			return false
		}
		if !strings.Contains(raw, "/") && strings.Contains(raw, ".") && !isStaticExt("/"+raw) {
			switch strings.ToLower(path.Ext(raw)) {
			case ".json", ".php", ".aspx", ".jsp", ".do", ".html", ".htm", ".xml", ".txt":
			default:
				return false // "errors.not_found", "a.b.c"
			}
		}
	}
	return true
}

var nextInternalPages = map[string]bool{"/_app": true, "/_document": true, "/_error": true}

// ─── lineIndex ────────────────────────────────────────────────────────────────

type lineIndex struct{ starts []int }

func buildLineIndex(content string) *lineIndex {
	starts := []int{0}
	for i := 0; i < len(content); {
		j := strings.IndexByte(content[i:], '\n')
		if j < 0 {
			break
		}
		i += j + 1
		starts = append(starts, i)
	}
	return &lineIndex{starts: starts}
}

func (li *lineIndex) lineAt(pos int) int {
	return sort.Search(len(li.starts), func(i int) bool { return li.starts[i] > pos })
}

func (li *lineIndex) lineCol(pos int) (int, int) {
	l := li.lineAt(pos)
	if l < 1 {
		return 1, pos + 1
	}
	return l, pos - li.starts[l-1] + 1
}

// validHTTPMethod: only real verbs pass; router "USE"/"ALL" etc fall back to DefaultMethod.
func validHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// ─── Atribusi method via variabel (fetch(VAR,{method}) / axios.post(VAR)) ─────

var reVarAssignAnch = regexp.MustCompile(`^([A-Za-z_$][A-Za-z0-9_$]{0,63})\s*[=:]\s*["'](https?://[^'"` + "`" + `\s<>(){}|\\^]+)["']`)

var (
	reVarFetchM    = regexp.MustCompile(`fetch\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*\{[^}]{0,400}method\s*:\s*['"]([A-Za-z]+)['"]`)
	reVarAxiosM    = regexp.MustCompile(`axios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)`)
	reVarAxiosCfg1 = regexp.MustCompile(`axios\s*\(\s*\{[^}]{0,300}url\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)[^}]{0,300}method\s*:\s*['"]([A-Za-z]+)['"]`)
	reVarAxiosCfg2 = regexp.MustCompile(`axios\s*\(\s*\{[^}]{0,300}method\s*:\s*['"]([A-Za-z]+)['"]\s*,[^}]{0,300}url\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)`)
	reVarAjax      = regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]{0,300}url\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)[^}]{0,300}(?:method|type)\s*:\s*['"]([A-Za-z]+)['"]`)
	reVarJQ        = regexp.MustCompile(`\$\.(get|post)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)`)
	reVarXHR       = regexp.MustCompile(`\.open\s*\(\s*['"]([A-Za-z]+)['"]\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)`)
)

// collectVarURLs: namaVar(lower) -> URL absolut (first wins).
// Kandidat dicari dari `"http` / `'http`, mundur ke `NAME =|:`.
func collectVarURLs(content string) map[string]string {
	out := map[string]string{}
	if !strings.Contains(content, "://") {
		return out
	}
	start := func(p int) int {
		i := p - 1
		for i >= 0 && isWSByte(content[i]) {
			i--
		}
		if i < 0 || (content[i] != '=' && content[i] != ':') {
			return -1
		}
		i--
		for i >= 0 && isWSByte(content[i]) {
			i--
		}
		j := i
		for j >= 0 && isIdentByte(content[j]) {
			j--
		}
		if j == i || j < 0 || strings.IndexByte(" \t\n\r,{(;", content[j]) < 0 {
			return -1
		}
		return j + 1
	}
	starts := anchorStarts(content, []string{`"http`, `'http`}, start)
	for _, m := range anchoredFind(content, reVarAssignAnch, starts, 2200, nil) {
		k := strings.ToLower(content[m[2]:m[3]])
		if _, ok := out[k]; !ok {
			out[k] = content[m[4]:m[5]]
		}
	}
	return out
}

// resolveVarCallMethods: absURL(lower) -> METHOD. Prefer non-GET saat konflik.
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
	type spec struct {
		re         *regexp.Regexp
		varG, mthG int
		need       string
	}
	for _, sp := range []spec{
		{reVarFetchM, 1, 2, "fetch"}, {reVarAxiosM, 2, 1, "axios"}, {reVarAxiosCfg1, 1, 2, "axios"},
		{reVarAxiosCfg2, 2, 1, "axios"}, {reVarAjax, 1, 2, "$.ajax"}, {reVarJQ, 2, 1, "$."}, {reVarXHR, 2, 1, ".open"},
	} {
		if !strings.Contains(content, sp.need) {
			continue
		}
		for _, m := range sp.re.FindAllStringSubmatch(content, -1) {
			put(m[sp.varG], m[sp.mthG])
		}
	}
	return out
}

// ─── Core Extractor ───────────────────────────────────────────────────────────

type contentKind int

const (
	ckJS contentKind = iota
	ckJSON
	ckHTML
)

func detectContentKind(ctype, pageURL, content string) contentKind {
	ct := strings.ToLower(ctype)
	switch {
	case strings.Contains(ct, "html"):
		return ckHTML
	case strings.Contains(ct, "json"):
		return ckJSON
	case strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript"):
		return ckJS
	}
	head := content
	if len(head) > 1024 {
		head = head[:1024]
	}
	h := strings.ToLower(strings.TrimSpace(head))
	if strings.HasPrefix(h, "<!doctype html") || strings.HasPrefix(h, "<html") ||
		(strings.HasPrefix(h, "<") && (strings.Contains(h, "<head") || strings.Contains(h, "<body") || strings.Contains(h, "<script"))) {
		return ckHTML
	}
	if strings.HasPrefix(h, "{") || strings.HasPrefix(h, "[") {
		if strings.HasSuffix(strings.ToLower(pathOf(pageURL)), ".js") {
			return ckJS
		}
		return ckJSON
	}
	return ckJS
}

func isYAML(ctype, pageURL string) bool {
	p := strings.ToLower(pathOf(pageURL))
	return strings.Contains(strings.ToLower(ctype), "yaml") || strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")
}

func pathOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Path
	}
	return raw
}

// ExtractOptions: parameter ekstraksi satu record.
type ExtractOptions struct {
	SourceLabel     string // label source (default PageURL)
	PageURL         string // URL record (dasar resolusi)
	BaseOverride    string // -b
	ContentType     string
	IncludeAssets   bool
	IncludeExternal bool
	InScope         func(host string) bool // nil = tanpa scope (hanya utk pemilihan base)
}

type ExtractResult struct {
	Endpoints       []Endpoint
	Base            string
	SkippedExternal int
	ScriptRefs      []string // <script src> absolut (record HTML)
	DocOrigin       string   // origin dokumen efektif (HTML, setelah <base>)
}

type extractor struct {
	o           ExtractOptions
	ck          contentKind
	orig        string
	c           string
	lower       string
	nt          normText
	li          *lineIndex
	pageOrigin  string
	docBase     string
	declBase    string
	electedBase string
	effBase     string
	varMethods  map[string]string
	eps         []Endpoint
	skippedExt  map[string]bool
}

func (x *extractor) lowerC() string {
	if x.lower == "" && x.c != "" {
		x.lower = asciiLower(x.c)
	}
	return x.lower
}

// extractEndpoints (kompat): API lama -> (endpoint, base efektif, jumlah external di-skip).
func extractEndpoints(content, sourceURL, jsURL, baseOverride string, includeAssets, includeExternal bool) ([]Endpoint, string, int) {
	r := Extract(content, ExtractOptions{
		SourceLabel: sourceURL, PageURL: jsURL, BaseOverride: baseOverride,
		IncludeAssets: includeAssets, IncludeExternal: includeExternal,
	})
	return r.Endpoints, r.Base, r.SkippedExternal
}

func Extract(content string, o ExtractOptions) ExtractResult {
	if o.SourceLabel == "" {
		o.SourceLabel = o.PageURL
	}
	x := &extractor{o: o, orig: content, skippedExt: map[string]bool{}}
	x.ck = detectContentKind(o.ContentType, o.PageURL, content)
	x.nt = normaliseContentEP(content, x.ck)
	x.c = x.nt.s
	x.pageOrigin = originOf(o.PageURL)
	x.docBase = o.PageURL
	var res ExtractResult

	if x.ck == ckHTML {
		if m := reBaseHref.FindStringSubmatch(x.c); m != nil {
			if b := resolveAgainst(o.PageURL, strings.TrimSpace(m[1])); b != "" && extractHost(b) != "" {
				x.docBase = b
			}
		}
		res.DocOrigin = originOf(x.docBase)
		for _, m := range reScriptSrc.FindAllStringSubmatch(x.c, -1) {
			if r, _, _ := x.resolve(strings.TrimSpace(m[1]), kHTML); r != "" {
				res.ScriptRefs = append(res.ScriptRefs, r)
			}
		}
	}

	if o.BaseOverride != "" {
		x.effBase = o.BaseOverride
	} else {
		x.declBase = detectDeclaredBase(x.c, x.lowerC(), o.PageURL, o.InScope)
		if x.declBase == "" {
			x.electedBase = detectElectedBase(x.c, o.InScope)
		}
		switch {
		case x.declBase != "":
			x.effBase = x.declBase
		case x.electedBase != "":
			x.effBase = x.electedBase
		case x.ck == ckHTML:
			x.effBase = originOf(x.docBase)
		default:
			x.effBase = x.pageOrigin
		}
	}
	x.varMethods = resolveVarCallMethods(x.c, collectVarURLs(x.c))
	yaml := isYAML(o.ContentType, o.PageURL)

	claimed := map[int]bool{}
	for pi := range extractionPatterns {
		pat := &extractionPatterns[pi]
		if (pat.HTMLOnly && x.ck != ckHTML) || (pat.AssetOnly && !o.IncludeAssets) || (pat.YAMLOnly && !yaml) {
			continue
		}
		for _, loc := range pat.findAll(x.c, x.lowerC) {
			s, e := loc[pat.URLGroup*2], loc[pat.URLGroup*2+1]
			if s < 0 || e < 0 || claimed[s] {
				// literal yg sama sudah diklaim pola yang lebih spesifik
				// (api.get("/x") jangan diulang generic-quoted-path ke origin lain)
				continue
			}
			kind, args, validate := pat.Kind, pat.Args, pat.Validate
			if pat.KeyGroup > 0 && loc[pat.KeyGroup*2] >= 0 {
				if routeKeys[strings.ToLower(x.c[loc[pat.KeyGroup*2]:loc[pat.KeyGroup*2+1]])] {
					kind = kRoute
				}
			}
			method, explicit := "", false
			if pat.MethodGroup > 0 && loc[pat.MethodGroup*2] >= 0 {
				method = strings.ToUpper(x.c[loc[pat.MethodGroup*2]:loc[pat.MethodGroup*2+1]])
				explicit = validHTTPMethod(method)
				if !explicit {
					method = ""
				}
			}
			if pat.Receiver {
				mc := classifyMember(x.c, loc[0], x.c[loc[pat.MethodGroup*2]:loc[pat.MethodGroup*2+1]], x.c[s:e])
				if !mc.ok {
					continue
				}
				kind, args, validate = mc.kind, mc.args, mc.validate
			}
			if pat.ForceMethod {
				method, explicit = pat.DefaultMethod, true
			}
			if x.emit(pat, kind, args, validate, s, e, method, explicit) {
				claimed[s] = true
			}
		}
	}
	if x.ck == ckHTML {
		x.extractForms()
	}

	res.Endpoints = mergeEndpoints(sortByPos(x.eps))
	res.Base = x.effBase
	res.SkippedExternal = len(x.skippedExt)
	return res
}

// extractForms: <form action method> (method atribut -> eksplisit).
func (x *extractor) extractForms() {
	pat := &ExtractionPattern{Name: "html-form", Kind: kHTML, DefaultMethod: "GET"}
	for _, loc := range reFormTag.FindAllStringSubmatchIndex(x.c, -1) {
		attrs := x.c[loc[2]:loc[3]]
		am := reFormAction.FindStringSubmatchIndex(attrs)
		if am == nil || am[3] <= am[2] {
			continue
		}
		method, explicit := "", false
		if mm := reFormMethod.FindStringSubmatch(attrs); mm != nil {
			if m := strings.ToUpper(mm[1]); validHTTPMethod(m) {
				method, explicit = m, true
			}
		}
		x.emit(pat, kHTML, argNone, nil, loc[2]+am[2], loc[2]+am[3], method, explicit)
	}
}

func sortByPos(eps []Endpoint) []Endpoint {
	sort.SliceStable(eps, func(i, j int) bool { return eps[i].pos < eps[j].pos })
	return eps
}

// resolve: raw -> (abs, pageRel, relPath). abs "" = ditolak.
func (x *extractor) resolve(raw string, kind patKind) (string, bool, string) {
	raw = normaliseTemplateURL(raw)
	if raw == "" {
		return "", false, ""
	}
	if sch := reSchemeEP.FindString(raw); sch != "" {
		switch strings.ToLower(strings.TrimSuffix(sch, ":")) {
		case "http", "https", "ws", "wss":
			return cleanAbs(raw), false, ""
		}
		return "", false, "" // javascript:, mailto:, tel:, data:, blob:, ...
	}
	if strings.HasPrefix(raw, "//") {
		b := x.o.BaseOverride
		if b == "" {
			b = x.o.PageURL
		}
		scheme := "https"
		if bu, err := url.Parse(b); err == nil && bu.Scheme != "" {
			scheme = bu.Scheme
		}
		return cleanAbs(scheme + ":" + raw), false, ""
	}
	if x.o.BaseOverride != "" {
		return resolveAgainst(x.o.BaseOverride, raw), false, ""
	}
	if x.ck == ckHTML || kind == kHTML {
		return resolveAgainst(x.docBase, raw), false, ""
	}
	if kind == kModule {
		return resolveAgainst(x.o.PageURL, raw), false, ""
	}
	api := apiShapedEP(raw)
	if x.declBase != "" && kind != kRoute && (kind == kInstance || api) {
		return joinBase(x.declBase, raw), false, ""
	}
	if x.electedBase != "" && kind != kRoute && api {
		return resolveAgainst(x.electedBase, rootify(raw)), false, ""
	}
	if x.pageOrigin == "" {
		return raw, false, "" // file lokal tanpa -b: tetap relatif
	}
	rel := rootify(raw)
	return resolveAgainst(x.pageOrigin, rel), true, rel
}

// htmlTagAt: nama tag HTML yang memuat offset pos (lowercase), "" bila tak ada.
func htmlTagAt(c string, pos int) string {
	from := pos - 2000
	if from < 0 {
		from = 0
	}
	lt := strings.LastIndexByte(c[from:pos], '<')
	if lt < 0 {
		return ""
	}
	lt += from
	if strings.IndexByte(c[lt:pos], '>') >= 0 {
		return ""
	}
	j := lt + 1
	for j < len(c) && j < lt+20 && (isIdentByte(c[j]) || c[j] == '-') {
		j++
	}
	return strings.ToLower(c[lt+1 : j])
}

// emit: proses satu kandidat; true bila endpoint dicatat.
func (x *extractor) emit(pat *ExtractionPattern, kind patKind, args argStyle, validate func(string) bool, s, e int, method string, explicit bool) bool {
	c := x.c
	raw := strings.TrimSpace(c[s:e])
	if len(raw) < 2 {
		return false
	}
	if validate != nil && !validate(raw) {
		return false
	}
	if x.ck == ckHTML {
		switch htmlTagAt(c, s) {
		case "base", "link", "script", "img", "meta":
			return false // <base href> = base dokumen; <link>/<script>/<img> = aset
		}
	}
	raw = normaliseTemplateURL(raw)
	if len(raw) < 2 || !validCandidate(raw, kind) {
		return false
	}
	abs, pageRel, rel := x.resolve(raw, kind)
	if abs == "" {
		return false
	}
	if strings.Contains(abs, "://") {
		u, err := url.Parse(abs)
		if err != nil || u.Host == "" {
			return false
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "ws", "wss":
		default:
			return false
		}
		if nextInternalPages[u.Path] {
			return false
		}
	}
	if !x.o.IncludeAssets {
		// PageRel: host-nya bisa diganti (CDN -> origin app) -> cek host di akhir.
		if isStaticExt(abs) || (!pageRel && isStaticHost(extractHost(abs))) {
			return false
		}
	}
	if !x.o.IncludeExternal {
		if !sameSite(extractHost(x.effBase), extractHost(abs)) {
			x.skippedExt[strings.ToLower(abs)] = true
			return false
		}
	}

	// ── method & params dari konteks ──
	var ci ctxInfo
	q := s - 1
	quoted := q >= 0 && (c[q] == '"' || c[q] == '\'' || c[q] == '`')
	switch {
	case !quoted:
	case kind == kConfig:
		ci = analyzeObject(c, q)
	case kind == kRoute || kind == kHTML || kind == kModule:
	default:
		if open := callOpenBefore(c, q); open >= 0 {
			style := args
			if style == argNone && (kind == kLiteral || kind == kAbs) {
				style = argOptions
			}
			ci = analyzeCall(c, open, style, method)
		}
	}
	if !explicit && ci.method != "" {
		method, explicit = ci.method, true
	}
	if !explicit {
		if vm, ok := x.varMethods[strings.ToLower(abs)]; ok {
			method, explicit = vm, true
		}
	}
	if !explicit {
		method = strings.ToUpper(pat.DefaultMethod)
		if method == "" {
			method = "GET"
		}
		if p := strings.ToLower(pathOf(abs)); strings.HasSuffix(p, "/graphql") || strings.HasSuffix(p, "/graphql/") {
			method, explicit = "POST", true // Apollo/urql default POST
		}
	}
	query, body := ci.query, ci.body
	if !isBodyMethod(method) {
		query = append(query, body...)
		body = nil
	}
	params := dedupStrings(append(append(urlParams(raw), query...), body...))

	op := x.nt.orig(s)
	if x.li == nil {
		x.li = buildLineIndex(x.orig)
	}
	line, col := x.li.lineCol(op)
	x.eps = append(x.eps, Endpoint{
		RawURL:         raw,
		AbsURL:         abs,
		Method:         method,
		Params:         params,
		Source:         fmt.Sprintf("%s:%d:%d", x.o.SourceLabel, line, col),
		Line:           line,
		Col:            col,
		Interest:       scoreInterest(abs),
		MethodExplicit: explicit,
		QueryParams:    dedupStrings(query),
		BodyKeys:       dedupStrings(body),
		PageRel:        pageRel,
		RelPath:        rel,
		PageURL:        x.o.PageURL,
		pos:            op,
	})
	return true
}

func dedupStrings(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(xs))
	var out []string
	for _, v := range xs {
		v = strings.TrimSpace(v)
		if v == "" || len(v) >= 40 || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func mergeParams(dst *Endpoint, src Endpoint) {
	dst.Params = dedupStrings(append(dst.Params, src.Params...))
	dst.QueryParams = dedupStrings(append(dst.QueryParams, src.QueryParams...))
	dst.BodyKeys = dedupStrings(append(dst.BodyKeys, src.BodyKeys...))
}

// mergeEndpoints: gabung per URL (urutan masukan dipertahankan = deterministik).
// Ada method eksplisit -> satu record per method eksplisit (GET default dari
// literal generik dilebur); tanpa eksplisit -> satu record.
func mergeEndpoints(eps []Endpoint) []Endpoint {
	var order []string
	groups := map[string][]int{}
	for i := range eps {
		k := dedupKey(eps[i].AbsURL)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}
	out := make([]Endpoint, 0, len(order))
	for _, k := range order {
		idxs := groups[k]
		hasExplicit := false
		for _, i := range idxs {
			if eps[i].MethodExplicit {
				hasExplicit = true
				break
			}
		}
		byMethod := map[string]int{}
		firstOut := -1
		for _, i := range idxs {
			e := eps[i]
			if hasExplicit && !e.MethodExplicit {
				continue
			}
			if j, ok := byMethod[e.Method]; ok {
				mergeParams(&out[j], e)
				continue
			}
			byMethod[e.Method] = len(out)
			if firstOut < 0 {
				firstOut = len(out)
			}
			out = append(out, e)
		}
		if hasExplicit {
			for _, i := range idxs {
				if !eps[i].MethodExplicit {
					mergeParams(&out[firstOut], eps[i])
				}
			}
		}
	}
	return out
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

// ─── Known URL Normalisation ──────────────────────────────────────────────────

// hostKey: hostname lowercase + port non-default (443/80 dibuang).
func hostKey(u *url.URL) string {
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	switch p := u.Port(); p {
	case "", "80", "443":
		return h
	default:
		return h + ":" + p
	}
}

// normaliseForFilter: kunci -k level host+path (skema/query/fragment/trailing
// slash/port default diabaikan). Baris tanpa skema ("example.com/x") ikut.
func normaliseForFilter(rawURL string) string {
	raw := strings.TrimSpace(rawURL)
	if !strings.Contains(raw, "://") && !strings.HasPrefix(raw, "/") {
		hostPart := raw
		if i := strings.IndexAny(raw, "/?#"); i >= 0 {
			hostPart = raw[:i]
		}
		if strings.Contains(hostPart, ".") {
			raw = "http://" + raw
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(strings.TrimRight(raw, "/"))
	}
	p := strings.TrimRight(u.EscapedPath(), "/")
	if p == "" {
		p = "/"
	}
	return hostKey(u) + fixBraces(p)
}
