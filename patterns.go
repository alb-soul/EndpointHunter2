package main

// ============================================================
// patterns.go — tabel pola + mesin pencarian ber-anchor
//
// Dulu: ~25 regex tanpa prefix literal di-scan ke SELURUH konten (Go RE2 =
// NFA di tiap byte, ~4MB/s per pola) -> bundle 10MB ≈ menit. Kini: posisi
// kandidat dicari dengan strings.Index pada anchor literal, lalu regex
// TER-ANCHOR (^) hanya dijalankan di posisi itu (mati dalam beberapa byte bila
// tak cocok). Pola tanpa anchor di konten = nol biaya.
// ============================================================

import (
	"regexp"
	"sort"
	"strings"
)

type patKind int

const (
	kCall     patKind = iota // HTTP call, URL = argumen pertama
	kInstance                // client instance (api.get / this.http.post / axios.get)
	kConfig                  // URL sebagai nilai key di objek config ({url, method})
	kRoute                   // route / navigasi halaman -> selalu origin halaman
	kLiteral                 // literal string generik
	kAbs                     // URL absolut
	kHTML                    // atribut HTML -> base dokumen
	kModule                  // import()/sourcemap -> relatif ke file (aset)
)

type ExtractionPattern struct {
	Name    string
	Src     string         // regex (tanpa ^); match HARUS dimulai di posisi start
	Regex   *regexp.Regexp // "^(?:Src)" — dijalankan di tiap posisi kandidat
	Anchors []string       // literal penanda kandidat (kosong = scan penuh)
	Fold    bool           // anchor dicari di salinan lowercase ASCII
	Back    int            // start = posisi anchor - Back
	Start   func(c string, p int) int
	Pre     func(c string, st int) bool // cek konteks sebelum start
	MaxLen  int

	URLGroup      int
	MethodGroup   int
	KeyGroup      int // url-var: nama key menentukan kind (route vs config)
	DefaultMethod string
	ForceMethod   bool // DefaultMethod dianggap eksplisit (sendBeacon = POST)
	Kind          patKind
	Args          argStyle
	Receiver      bool // .get/.post(...): kind/args/validasi ditentukan receiver
	HTMLOnly      bool
	AssetOnly     bool // hanya dgn --include-assets
	YAMLOnly      bool
	Validate      func(string) bool

	full *regexp.Regexp // scan penuh (pola tanpa anchor)
}

const bt = `['"\x60]`
const bte = `'"\x60`

func identBoundary(c string, st int) bool { return st == 0 || !isIdentByte(c[st-1]) }

// keyBoundary: awal key objek/assignment: didahului , { ( ; spasi, atau quote
// pembuka key JSON ("url": ...).
func keyBoundary(c string, st int) bool {
	i := st - 1
	if i >= 0 && (c[i] == '"' || c[i] == '\'') {
		i--
	}
	return i < 0 || strings.IndexByte(",{(; \t\n\r", c[i]) >= 0
}

// newBoundary: Request/EventSource/WebSocket/URL harus didahului `new`;
// fetch boleh apa saja (ofetch/$fetch/prefetch juga panggilan HTTP).
func newBoundary(c string, st int) bool {
	if strings.HasPrefix(c[st:], "fetch") {
		return true
	}
	i := st - 1
	for i >= 0 && isWSByte(c[i]) {
		i--
	}
	return i >= 2 && i < st-1 && c[i-2:i+1] == "new" && (i < 3 || !isIdentByte(c[i-3]))
}

// locationPre: `location=` / `window.location=` (bukan obj.location / geolocation).
func locationPre(c string, st int) bool {
	if st == 0 {
		return true
	}
	p := c[st-1]
	if isIdentByte(p) {
		return false
	}
	if p != '.' {
		return true
	}
	j := st - 2
	k := j
	for k >= 0 && isIdentByte(c[k]) {
		k--
	}
	switch c[k+1 : j+1] {
	case "window", "document", "self", "top":
		return k < 0 || (!isIdentByte(c[k]) && c[k] != '.')
	}
	return false
}

// absStart: anchor "://" -> mundur ke quote pembuka sebelum skema.
func absStart(c string, p int) int {
	i := p - 1
	for i >= 0 && p-i <= 5 && ((c[i] >= 'a' && c[i] <= 'z') || (c[i] >= 'A' && c[i] <= 'Z')) {
		i--
	}
	if i < 0 || i == p-1 || (c[i] != '"' && c[i] != '\'' && c[i] != '`') {
		return -1
	}
	return i
}

var quoteSlash = []string{`"/`, `'/`, "`/"}

var extractionPatterns = []ExtractionPattern{
	{
		Name: "fetch-family", Src: `(?:fetch|Request|EventSource|WebSocket|URL)\s*\(\s*` + bt + `([^` + bte + `\s]{2,})` + bt,
		Anchors: []string{"fetch", "Request", "EventSource", "WebSocket", "URL"}, Pre: newBoundary,
		URLGroup: 1, DefaultMethod: "GET", Kind: kCall, Args: argOptions,
	},
	{
		Name: "sendBeacon", Src: `sendBeacon\s*\(\s*` + bt + `([^` + bte + `\s]{2,})` + bt,
		Anchors:  []string{"sendBeacon"},
		URLGroup: 1, DefaultMethod: "POST", ForceMethod: true, Kind: kCall,
	},
	{
		// axios.get / api.post / this.http.get / $.get / ky.post / router.get / app.use ...
		Name: "member-call", Src: `\.\s*\$?(getJSON|get|post|put|delete|patch|head|options|all|use)\s*(?:<[^<>()]{0,80}>)?\s*\(\s*` + bt + `([^` + bte + `\s]{2,})` + bt,
		Anchors: []string{".get", ".post", ".put", ".delete", ".patch", ".head", ".options", ".use", ".all",
			".$get", ".$post", ".$put", ".$delete", ".$patch", ". get", ". post"},
		URLGroup: 2, MethodGroup: 1, DefaultMethod: "GET", Receiver: true,
	},
	{
		Name: "XHR.open", Src: `\.open\s*\(\s*['"]([A-Za-z]+)['"]\s*,\s*` + bt + `([^` + bte + `\s]{2,})` + bt,
		Anchors:  []string{".open"},
		URLGroup: 2, MethodGroup: 1, DefaultMethod: "GET", Kind: kCall,
	},
	{
		Name: "$.ajax(config)", Src: `\$\.ajax\s*\(\s*\{[^{}]{0,300}?\burl\s*:\s*` + bt + `([^` + bte + `\s]{2,})` + bt,
		Anchors: []string{"$.ajax"}, MaxLen: 1500,
		URLGroup: 1, DefaultMethod: "GET", Kind: kConfig,
	},
	{
		Name: "$.ajax(url,settings)", Src: `\$\.ajax\s*\(\s*` + bt + `([^` + bte + `\s]{2,})` + bt,
		Anchors:  []string{"$.ajax"},
		URLGroup: 1, DefaultMethod: "GET", Kind: kCall, Args: argOptions,
	},
	{
		Name: "url-var-assignment",
		Src:  `(?i)(url|uri|endpoint|apiPath|apiUrl|apiEndpoint|baseUrl|actionUrl|path|href|action|to|redirectTo|redirectUrl|redirect|link)['"]?\s*[=:]\s*` + bt + `((?:https?://|wss?://|/)[^` + bte + `\s<>|\\^]{2,})` + bt,
		Anchors: []string{"url", "uri", "endpoint", "apipath", "apiurl", "apiendpoint", "baseurl", "actionurl",
			"path", "href", "action", "to", "redirectto", "redirecturl", "redirect", "link"},
		Fold: true, Pre: keyBoundary,
		URLGroup: 2, KeyGroup: 1, DefaultMethod: "GET", Kind: kConfig,
	},
	{
		Name:    "angular-route",
		Src:     `path\s*:\s*['"]([A-Za-z0-9_\-:.*/]{1,120})['"]\s*,\s*(?:component|loadChildren|loadComponent|redirectTo|children|canActivate|canLoad|canMatch|pathMatch|resolve|data|title|outlet)\s*:`,
		Anchors: []string{"path"}, Pre: identBoundary,
		URLGroup: 1, DefaultMethod: "GET", Kind: kRoute,
	},
	{
		Name:    "angular-route-rev",
		Src:     `(?:component|loadComponent)\s*:\s*[A-Za-z_$][\w$.]*\s*,\s*path\s*:\s*['"]([A-Za-z0-9_\-:.*/]{1,120})['"]`,
		Anchors: []string{"component", "loadComponent"}, Pre: identBoundary,
		URLGroup: 1, DefaultMethod: "GET", Kind: kRoute,
	},
	{
		Name: "location-assign", Src: `location(?:\.href)?\s*=\s*` + bt + `([^` + bte + `\s\\]{2,})` + bt,
		Anchors: []string{"location"}, Pre: locationPre,
		URLGroup: 1, DefaultMethod: "GET", Kind: kRoute,
	},
	{
		Name: "location-call", Src: `(?:location\s*\.\s*(?:assign|replace)|window\s*\.\s*open)\s*\(\s*` + bt + `([^` + bte + `\s\\]{2,})` + bt,
		Anchors: []string{"location", "window"}, Pre: identBoundary,
		URLGroup: 1, DefaultMethod: "GET", Kind: kRoute,
	},
	{
		Name: "href-assign", Src: `\.[Hh][Rr][Ee][Ff]\s*=\s*` + bt + `([^` + bte + `\s\\]{2,})` + bt,
		Anchors:  []string{".href", ".HREF", ".Href"},
		URLGroup: 1, DefaultMethod: "GET", Kind: kRoute,
	},
	{
		Name:     "api-path-literal",
		Src:      `['"\x60](\/(?:api|v\d+|internal|admin|auth|rest|graphql|_api|service|backend|private|management|debug|config|webhook|callback|oauth|token|user|account|payment|order|search|upload|download|export|import|report|dashboard|panel|portal|rpc|ws|socket)[\/a-zA-Z0-9_\-\.{}:@!$&()*+,;=%?#\[\]]{2,})['"\x60]`,
		Anchors:  quoteSlash,
		URLGroup: 1, DefaultMethod: "GET", Kind: kLiteral, Validate: validGenericPathEP,
	},
	{
		Name:    "absolute-url",
		Src:     `['"\x60]((?:https?|wss?)://[a-zA-Z0-9\-\.]+(?::[0-9]+)?/[^\s'"\x60<>()|\\^]{3,})['"\x60]`,
		Anchors: []string{"://"}, Start: absStart,
		URLGroup: 1, DefaultMethod: "GET", Kind: kAbs,
	},
	{
		Name: "generic-quoted-path", Src: bt + `(\/[^\s` + bte + `\\<>]{2,})` + bt,
		Anchors:  quoteSlash,
		URLGroup: 1, DefaultMethod: "GET", Kind: kLiteral, Validate: validGenericPathEP,
	},
	{
		Name:     "bare-path-prose",
		Src:      `[\s(,;](\/(?:[A-Za-z0-9_~.\-%]+\/)+[A-Za-z0-9_~.\-%?#\/]*)`,
		Anchors:  []string{" /", "(/", ",/", ";/", "\n/", "\t/", "\r/"},
		URLGroup: 1, DefaultMethod: "GET", Kind: kLiteral, Validate: validBarePath,
	},
	{
		Name: "json-path-key", Src: `"(\/[^"\s\\]{1,120})"\s*:`,
		Anchors:  []string{`"/`},
		URLGroup: 1, DefaultMethod: "GET", Kind: kLiteral, Validate: validGenericPathEP,
	},
	{
		Name: "yaml-path-key", Src: `(?m)^[ \t]*(\/[^:\s]{1,120})\s*:`, YAMLOnly: true,
		URLGroup: 1, DefaultMethod: "GET", Kind: kLiteral, Validate: validGenericPathEP,
	},
	{
		Name:    "html-attr",
		Src:     `(?i)\s(?:href|action|formaction|data-(?:url|href|endpoint|api|action|src-url))\s*=\s*["']([^"'<>\s]{1,400})["']`,
		Anchors: []string{"href", "action", "formaction", "data-"}, Fold: true, Back: 1, HTMLOnly: true,
		URLGroup: 1, DefaultMethod: "GET", Kind: kHTML,
	},
	{
		Name: "dynamic-import", Src: `import\s*\(\s*` + bt + `([^` + bte + `\s]{2,})` + bt + `\s*\)`,
		Anchors: []string{"import"}, Pre: identBoundary, AssetOnly: true,
		URLGroup: 1, DefaultMethod: "GET", Kind: kModule,
	},
	{
		Name: "sourcemap", Src: `sourceMappingURL\s*=\s*([^\s'"*]+)`,
		Anchors: []string{"sourceMappingURL"}, AssetOnly: true,
		URLGroup: 1, DefaultMethod: "GET", Kind: kModule,
	},
}

func init() {
	for i := range extractionPatterns {
		p := &extractionPatterns[i]
		p.Regex = regexp.MustCompile(`^(?:` + p.Src + `)`)
		if len(p.Anchors) == 0 {
			p.full = regexp.MustCompile(p.Src)
		}
		if p.MaxLen == 0 {
			// window kecil: backtracker RE2 membersihkan bitmap ~len(prog)*len(window)
			// per panggilan; URL literal >1KB praktis tak ada.
			p.MaxLen = 1100
		}
	}
}

// asciiLower: lowercase ASCII saja (panjang byte tetap -> offset sama).
func asciiLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// anchorStarts: posisi start unik (terurut) dari semua kemunculan anchor.
func anchorStarts(hay string, anchors []string, start func(p int) int) []int {
	var out []int
	for _, a := range anchors {
		for i := 0; i <= len(hay)-len(a); {
			j := strings.Index(hay[i:], a)
			if j < 0 {
				break
			}
			p := i + j
			i = p + 1
			if st := start(p); st >= 0 {
				out = append(out, st)
			}
		}
	}
	if len(out) < 2 {
		return out
	}
	sort.Ints(out)
	w := 1
	for i := 1; i < len(out); i++ {
		if out[i] != out[w-1] {
			out[w] = out[i]
			w++
		}
	}
	return out[:w]
}

// anchoredFind: jalankan re (ter-anchor ^) di tiap start; index absolut.
// Match yang tumpang-tindih dgn match sebelumnya dilewati (semantik FindAll).
func anchoredFind(c string, re *regexp.Regexp, starts []int, maxLen int, pre func(string, int) bool) [][]int {
	var out [][]int
	lastEnd := 0
	for _, st := range starts {
		if st < lastEnd || st >= len(c) {
			continue
		}
		if pre != nil && !pre(c, st) {
			continue
		}
		end := st + maxLen
		if end > len(c) {
			end = len(c)
		}
		loc := re.FindStringSubmatchIndex(c[st:end])
		if loc == nil {
			continue
		}
		for k := range loc {
			if loc[k] >= 0 {
				loc[k] += st
			}
		}
		out = append(out, loc)
		lastEnd = loc[1]
	}
	return out
}

// findAll: semua match pola di c (lower = salinan lowercase, lazy).
func (p *ExtractionPattern) findAll(c string, lower func() string) [][]int {
	if p.full != nil {
		return p.full.FindAllStringSubmatchIndex(c, -1)
	}
	hay := c
	if p.Fold {
		hay = lower()
	}
	start := func(i int) int { return i - p.Back }
	if p.Start != nil {
		start = func(i int) int { return p.Start(c, i) }
	}
	return anchoredFind(c, p.Regex, anchorStarts(hay, p.Anchors, start), p.MaxLen, p.Pre)
}

// ─── receiver member-call ────────────────────────────────────────────────────

var (
	strongReceivers = map[string]bool{"api": true, "apiClient": true, "axiosInstance": true, "instance": true,
		"http": true, "httpClient": true, "apiService": true, "restClient": true, "ajaxClient": true, "$http": true, "$api": true}
	weakReceivers   = map[string]bool{"client": true, "request": true, "req": true, "service": true, "got": true, "superagent": true, "agent": true, "https": true}
	routerReceivers = map[string]bool{"router": true, "app": true, "server": true, "fastify": true, "route": true}
)

// receiverBefore: identifier sebelum '.' di dot (this.http.get -> "http").
func receiverBefore(c string, dot int) string {
	i := dot - 1
	for i >= 0 && isWSByte(c[i]) {
		i--
	}
	j := i
	for j >= 0 && isIdentByte(c[j]) {
		j--
	}
	return c[j+1 : i+1]
}

type memberClass struct {
	kind     patKind
	args     argStyle
	validate func(string) bool
	ok       bool
}

// classifyMember: tentukan semantik .METHOD("x") dari receiver-nya.
func classifyMember(c string, dot int, method, raw string) memberClass {
	recv := receiverBefore(c, dot)
	m := strings.ToLower(method)
	slashOrAbs := strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")
	switch {
	case m == "all" || m == "use":
		if routerReceivers[recv] && strings.HasPrefix(raw, "/") {
			return memberClass{kind: kRoute, ok: true}
		}
		return memberClass{}
	case m == "getjson":
		return memberClass{kind: kCall, args: argJQ, validate: validLooseRelative, ok: recv == "$"}
	case recv == "axios" || recv == "$axios":
		return memberClass{kind: kInstance, args: argAxios, ok: true}
	case recv == "ky":
		return memberClass{kind: kCall, args: argOptions, ok: true}
	case recv == "$":
		return memberClass{kind: kCall, args: argJQ, validate: validLooseRelative, ok: true}
	case routerReceivers[recv]:
		return memberClass{kind: kRoute, ok: strings.HasPrefix(raw, "/")}
	case strongReceivers[recv]:
		return memberClass{kind: kInstance, args: argAxios, validate: validLooseRelative, ok: true}
	case weakReceivers[recv]:
		// request.get("Content-Type") = header express, client.get("key") = cache
		return memberClass{kind: kInstance, args: argAxios, validate: validPathOrURL, ok: true}
	default:
		// receiver tak dikenal (this.http, svc, ...): hanya path/URL eksplisit
		return memberClass{kind: kInstance, args: argAxios, ok: slashOrAbs}
	}
}
