package main

// Test audit 2026-11: tiap perbaikan punya kasus positif + negatif.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const pg = "https://app.example.com/static/js/main.js"

func ext(t *testing.T, js string) map[string]Endpoint {
	t.Helper()
	eps, _, _ := extractEndpoints(js, pg, pg, "", false, true)
	return epsByURL(eps)
}

func mustHave(t *testing.T, m map[string]Endpoint, u, method string) Endpoint {
	t.Helper()
	e, ok := m[u]
	if !ok {
		var got []string
		for k := range m {
			got = append(got, k)
		}
		t.Fatalf("missing %s (got %v)", u, got)
	}
	if method != "" && e.Method != method {
		t.Errorf("%s: method=%s want %s", u, e.Method, method)
	}
	return e
}

func mustNot(t *testing.T, m map[string]Endpoint, sub string) {
	t.Helper()
	for u := range m {
		if strings.Contains(u, sub) {
			t.Errorf("unexpected endpoint containing %q: %s", sub, u)
		}
	}
}

// ── decode escape aman ──
func TestDecodeEscapesSafe(t *testing.T) {
	u := `\` + "u" // dirangkai agar escape tidak ter-decode di sumber test
	m := ext(t, `var a="`+u+`002fapi`+u+`002fesc";var b="\/api\/json-slash";var c="\x2fapi\x2fhex";`)
	mustHave(t, m, "https://app.example.com/api/esc", "")
	mustHave(t, m, "https://app.example.com/api/json-slash", "")
	mustHave(t, m, "https://app.example.com/api/hex", "")
	// escape-u-0022 tidak boleh didecode jadi tanda kutip (memecah string literal)
	s, _ := decodeEscapesEP(`"say ` + u + `0022hi` + u + `0022"`)
	if strings.Count(s, `"`) != 2 {
		t.Errorf("structural quote decoded: %s", s)
	}
	s2, _ := decodeEscapesEP(`"a` + u + `000ab"`)
	if strings.Contains(s2, "\n") {
		t.Errorf("newline decoded (line drift): %q", s2)
	}
}

// ── source line:col akurat walau konten dinormalisasi ──
func TestSourceLineColMapping(t *testing.T) {
	js := "var x=1;\nvar a=\"/ap\"+\n\"i/joined\";\n  fetch(\"/api/after\");"
	m := ext(t, js)
	e := mustHave(t, m, "https://app.example.com/api/joined", "")
	if e.Line != 2 || e.Col < 7 || e.Col > 8 {
		t.Errorf("joined literal at %d:%d want 2:7..8", e.Line, e.Col)
	}
	e2 := mustHave(t, m, "https://app.example.com/api/after", "")
	if e2.Line != 4 || e2.Col != 10 { // kolom awal URL (setelah quote)
		t.Errorf("after-join literal at %d:%d want 4:10 (line drift)", e2.Line, e2.Col)
	}
	if !strings.HasSuffix(e2.Source, ":4:10") {
		t.Errorf("source format = %s want ...:line:col", e2.Source)
	}
}

// ── rekonstruksi route dinamis ──
func TestRouteReconstruction(t *testing.T) {
	m := ext(t, "var a=`/api/t/${ encodeURIComponent(n) }/z`;"+
		"var b=`${BASE_URL}/api/from-base`;"+
		`var c="/api/u/"+user.id+"/profile";`+
		`var d="".concat(e,"/api/orders/").concat(oid,"/items");`+
		`var q="/api/search?q="+term;`)
	mustHave(t, m, "https://app.example.com/api/t/{n}/z", "")
	mustHave(t, m, "https://app.example.com/api/from-base", "")
	mustHave(t, m, "https://app.example.com/api/u/{id}/profile", "")
	mustHave(t, m, "https://app.example.com/api/orders/{oid}/items", "")
	mustHave(t, m, "https://app.example.com/api/search?q={term}", "")
	mustNot(t, m, "BASE_URL")
	mustNot(t, m, "${")
}

func TestRouteReconstructionNegative(t *testing.T) {
	m := ext(t, `var a="/"+e;var b="/x"+y+"z";var c=`+"`${a}${b}`;")
	mustNot(t, m, "{e}")
	mustNot(t, m, "{y}")
}

// ── params tidak bocor ke panggilan tetangga ──
func TestParamsNoLeak(t *testing.T) {
	m := ext(t, `fetch("/api/a");fetch("/api/b",{method:"POST",body:JSON.stringify({secret:1,token:2})});`)
	a := mustHave(t, m, "https://app.example.com/api/a", "GET")
	if len(a.Params) != 0 {
		t.Errorf("params leaked into /api/a: %v", a.Params)
	}
	b := mustHave(t, m, "https://app.example.com/api/b", "POST")
	if !stringIn(b.Params, "secret") || !stringIn(b.Params, "token") {
		t.Errorf("body params missing: %v", b.Params)
	}
}

func TestMethodAndBodyFromCallArgs(t *testing.T) {
	m := ext(t, `axios.post("/api/login",{username:u,password:p});`+
		`axios.get("/api/list",{params:{page:1,size:2}});`+
		`$.ajax({url:"/api/legacy",type:"POST",data:{a:1}});`+
		`fetch("/api/nested",{headers:{"X-A":"1"},method:"PATCH"});`+
		`navigator.sendBeacon("/api/beacon",d);`+
		`new HttpLink({uri:"/graphql"});`)
	l := mustHave(t, m, "https://app.example.com/api/login", "POST")
	if !stringIn(l.BodyKeys, "username") || !stringIn(l.BodyKeys, "password") {
		t.Errorf("axios.post data keys: %v", l.BodyKeys)
	}
	li := mustHave(t, m, "https://app.example.com/api/list", "GET")
	if !stringIn(li.QueryParams, "page") {
		t.Errorf("axios.get params not query: %v", li.QueryParams)
	}
	mustHave(t, m, "https://app.example.com/api/legacy", "POST")
	mustHave(t, m, "https://app.example.com/api/nested", "PATCH")
	mustHave(t, m, "https://app.example.com/api/beacon", "POST")
	mustHave(t, m, "https://app.example.com/graphql", "POST")
	// enrich: query keys tetap di URL walau method POST
	e := enrichEndpoint(Endpoint{AbsURL: "https://x/api/p", Method: "POST", Params: []string{"page", "name"}, QueryParams: []string{"page"}})
	if !strings.Contains(e.URL, "page=FUZZ") || len(e.Body) != 1 || e.Body[0] != "name" {
		t.Errorf("enrich split wrong: %s %v", e.URL, e.Body)
	}
}

// ── skema non-web / MIME / tanggal / i18n / acak ditolak ──
func TestFalsePositiveFilters(t *testing.T) {
	m := ext(t, `a.href="javascript:void(0)";location.href="mailto:x@y";fetch("data:application/json;base64,e30");`+
		`var b="blob:https://app.example.com/1";var t="tel:+62";`+
		`var mime="application/json",d="2024/01/02",i="errors.not_found";`+
		`var r="/aB3dE9fGhJ2kLmN0pQ/zX9yW8vU7tS6rR5q";`+
		`var hdr=request.get("Content-Type"),env=app.get("env"),ck=client.get("cache-key");`+
		`var g=geolocation="nowhere/x";var png="/static/media/logo.5f3a.png";`)
	for _, bad := range []string{"javascript", "mailto", "data:", "blob:", "tel:", "application/json", "2024/01/02",
		"errors.not_found", "aB3dE9fG", "Content-Type", "/env", "cache-key", "nowhere", "logo.5f3a.png"} {
		mustNot(t, m, bad)
	}
}

func TestStaticFilterPathOnly(t *testing.T) {
	m := ext(t, `fetch("/api/assets.list");fetch("/api/x?ref=static.example.com");fetch("/img/a.png");`)
	mustHave(t, m, "https://app.example.com/api/assets.list", "")
	mustHave(t, m, "https://app.example.com/api/x?ref=static.example.com", "")
	mustNot(t, m, "a.png")
}

func TestInstanceReceivers(t *testing.T) {
	m := ext(t, `api.post("orders",{sku:s});this.http.get("/api/ng/items");svc.get("users");this.$axios.$get("/api/nuxt");`)
	mustHave(t, m, "https://app.example.com/orders", "POST")
	mustHave(t, m, "https://app.example.com/api/ng/items", "GET")
	mustHave(t, m, "https://app.example.com/api/nuxt", "GET")
	mustNot(t, m, "/users") // receiver tak dikenal + bare word
}

// ── base deklarasi: join ala axios, route tetap origin halaman ──
func TestDeclaredBaseJoin(t *testing.T) {
	m := ext(t, `const api=axios.create({baseURL:"https://api.example.com/api/v2"});api.get("/users/me");`+
		`api.post("orders");const r=[{path:"/admin/settings",component:S}];api.get("/api/v2/already");`)
	mustHave(t, m, "https://api.example.com/api/v2/users/me", "GET")
	mustHave(t, m, "https://api.example.com/api/v2/orders", "POST")
	mustHave(t, m, "https://api.example.com/api/v2/already", "")
	mustHave(t, m, "https://app.example.com/admin/settings", "")
	mustNot(t, m, "api.example.com/users/me")
	mustNot(t, m, "api/v2/admin")
}

func TestDeclaredBaseScopeAware(t *testing.T) {
	js := `var m=axios.create({baseURL:"https://api.mapbox-like.invalid"});fetch("/api/own");api.get("/x/y");`
	inScope := func(h string) bool { return h == "example.com" || strings.HasSuffix(h, ".example.com") }
	r := Extract(js, ExtractOptions{PageURL: pg, IncludeExternal: true, InScope: inScope})
	m := epsByURL(r.Endpoints)
	mustHave(t, m, "https://app.example.com/api/own", "")
	mustNot(t, m, "mapbox-like.invalid/api") // path relatif app tak dibajak
	mustNot(t, m, "mapbox-like.invalid/x")
	// tanpa scope: kandidat tetap dipakai (perilaku lama TestEnvBaseURLPatterns)
	r2 := Extract(js, ExtractOptions{PageURL: pg, IncludeExternal: true})
	if !strings.Contains(r2.Base, "mapbox") {
		t.Errorf("no-scope base = %s", r2.Base)
	}
}

func TestJSONConfigBase(t *testing.T) {
	cfg := `{"apiUrl":"https:\/\/api.example.com\/v1","paths":{"login":"\/auth\/login"}}`
	r := Extract(cfg, ExtractOptions{PageURL: "https://app.example.com/config.json", ContentType: "application/json", IncludeExternal: true})
	if r.Base != "https://api.example.com/v1" {
		t.Errorf("JSON-quoted key base not detected: %s", r.Base)
	}
	mustHave(t, epsByURL(r.Endpoints), "https://api.example.com/v1/auth/login", "")
}

// ── HTML: <base>, form, entity, aset ──
func TestHTMLExtraction(t *testing.T) {
	html := `<!doctype html><html><head><base href="/app/"><link href="/x.css" rel="stylesheet">` +
		`<script src="https://cdn.vendor.invalid/main.js"></script></head><body>` +
		`<div data-config="{&quot;u&quot;:&quot;/api/search?q=1&amp;p=2&quot;}"></div>` +
		`<form action="/account/login" method="post"></form><form action="edit"></form>` +
		`<a href="settings">s</a><a href="javascript:void(0)">x</a><a href="#top">t</a>` +
		`<script>fetch("rel/inline");fetch("/root/inline",{method:"DELETE"})</script></body></html>`
	r := Extract(html, ExtractOptions{PageURL: "https://app.example.com/", ContentType: "text/html", IncludeExternal: true})
	m := epsByURL(r.Endpoints)
	mustHave(t, m, "https://app.example.com/api/search?q=1&p=2", "")
	mustHave(t, m, "https://app.example.com/account/login", "POST")
	mustHave(t, m, "https://app.example.com/app/edit", "GET")
	mustHave(t, m, "https://app.example.com/app/settings", "")
	mustHave(t, m, "https://app.example.com/app/rel/inline", "")
	mustHave(t, m, "https://app.example.com/root/inline", "DELETE")
	mustNot(t, m, "&amp;")
	mustNot(t, m, "javascript")
	if _, ok := m["https://app.example.com/app/"]; ok {
		t.Errorf("<base href> emitted as endpoint")
	}
	if len(r.ScriptRefs) != 1 || r.ScriptRefs[0] != "https://cdn.vendor.invalid/main.js" || r.DocOrigin != "https://app.example.com" {
		t.Errorf("script refs %v origin %s", r.ScriptRefs, r.DocOrigin)
	}
}

// ── relatif di JS -> origin aplikasi + atribusi ulang CDN ──
func TestJSRelativeAndReattribution(t *testing.T) {
	cdn := "https://cdn.vendor.invalid/static/js/main.js"
	r := Extract(`fetch("api/rel");fetch("./api/dot");fetch("/api/root");`, ExtractOptions{PageURL: cdn, IncludeExternal: true})
	m := epsByURL(r.Endpoints)
	e := mustHave(t, m, "https://cdn.vendor.invalid/api/rel", "")
	if !e.PageRel || e.RelPath != "/api/rel" {
		t.Errorf("not marked page-relative: %+v", e)
	}
	mustHave(t, m, "https://cdn.vendor.invalid/api/dot", "")
	mustNot(t, m, "/static/js/api")
	refs := map[string]map[string]bool{scriptKey(cdn): {"https://app.example.com": true}}
	out := epsByURL(reattribute(r.Endpoints, refs))
	mustHave(t, out, "https://app.example.com/api/root", "")
	mustNot(t, out, "cdn.vendor.invalid")
	// JS yang tak direferensikan halaman mana pun: tetap
	kept := epsByURL(reattribute(r.Endpoints, map[string]map[string]bool{}))
	mustHave(t, kept, "https://cdn.vendor.invalid/api/root", "")
}

// ── router / manifest ──
func TestRouterManifests(t *testing.T) {
	m := ext(t, `self.__BUILD_MANIFEST={"/account/[id]":[a],"/blog/[...slug]":[b],"/_app":[c],"/_error":[d],`+
		`__rewrites:{afterFiles:[{source:"/api/proxy/:path*",destination:"https://backend.example.com/:path*"}]}};`+
		`const routes=[{path:"admin/users/:id",component:U},{path:"billing",loadChildren:()=>x}];`+
		`var r=[{path:"/dashboard/:tab",component:D}];`)
	mustHave(t, m, "https://app.example.com/account/{id}", "")
	mustHave(t, m, "https://app.example.com/blog/{slug}", "")
	mustHave(t, m, "https://app.example.com/api/proxy/:path*", "")
	mustHave(t, m, "https://backend.example.com/:path*", "")
	mustHave(t, m, "https://app.example.com/admin/users/:id", "")
	mustHave(t, m, "https://app.example.com/billing", "")
	mustHave(t, m, "https://app.example.com/dashboard/:tab", "")
	if _, ok := m["https://app.example.com/_app"]; ok {
		t.Errorf("/_app emitted")
	}
}

// ── propagasi: shadowing tetap dihormati ──
func TestPropagationShadowGuard(t *testing.T) {
	m := ext(t, `var u="https://api.example.com";function f(u){fetch(u+"/shadowed")}`)
	mustNot(t, m, "api.example.com/shadowed")
	m2 := ext(t, `var w="https://api.example.com";fetch(w+"/ok/path");`)
	mustHave(t, m2, "https://api.example.com/ok/path", "")
	m3 := ext(t, `var v="https://api.example.com";v+="/x";fetch(v+"/re");`)
	mustNot(t, m3, "api.example.com/re")
}

// ── performa: propagasi linear (dulu O(decl x size)) ──
func TestExtractLargeBundleFast(t *testing.T) {
	js := bundleMinified(1 << 20)
	st := time.Now()
	r := Extract(js, ExtractOptions{PageURL: pg})
	if d := time.Since(st); d > 8*time.Second {
		t.Fatalf("1MB bundle took %v", d)
	}
	if len(r.Endpoints) == 0 {
		t.Fatal("no endpoints")
	}
}

// ── skor interest berbasis token ──
func TestInterestTokens(t *testing.T) {
	for u, want := range map[string]string{
		"https://x.com/api/devices":     "MED",
		"https://x.com/latest/news":     "LOW",
		"https://x.com/interest/rates":  "LOW",
		"https://dev.x.com/home":        "HIGH",
		"https://x.com/administrator/x": "HIGH",
		"https://x.com/getUserProfile":  "MED",
		"https://x.com/static/app.js":   "LOW",
		"https://x.com/api/admin/users": "HIGH",
	} {
		if got := scoreInterest(u); got != want {
			t.Errorf("scoreInterest(%s)=%s want %s", u, got, want)
		}
	}
}

func TestEnrichColonOnlyPathSegment(t *testing.T) {
	e := enrichEndpoint(Endpoint{AbsURL: "https://x/v1/items:batchGet", Method: "GET"})
	if e.URL != "https://x/v1/items:batchGet" {
		t.Errorf("mid-segment colon fuzzed: %s", e.URL)
	}
	e2 := enrichEndpoint(Endpoint{AbsURL: "https://x/users/:id/posts", Method: "GET"})
	if e2.URL != "https://x/users/FUZZ/posts" {
		t.Errorf("path param not fuzzed: %s", e2.URL)
	}
}

// ── merge deterministik per method ──
func TestMergeEndpoints(t *testing.T) {
	in := []Endpoint{
		{AbsURL: "https://x/a", Method: "GET", Params: []string{"q"}},
		{AbsURL: "https://x/a", Method: "POST", MethodExplicit: true, Params: []string{"b"}},
		{AbsURL: "https://x/a", Method: "DELETE", MethodExplicit: true},
		{AbsURL: "https://x/c", Method: "GET"},
		{AbsURL: "https://x/c", Method: "GET", Params: []string{"z"}},
	}
	out := mergeEndpoints(in)
	if len(out) != 3 || out[0].Method != "POST" || out[1].Method != "DELETE" || out[2].AbsURL != "https://x/c" {
		t.Fatalf("merge = %+v", out)
	}
	if !stringIn(out[0].Params, "q") || !stringIn(out[2].Params, "z") {
		t.Errorf("params not merged: %v %v", out[0].Params, out[2].Params)
	}
}

// ── JSONL: baris raksasa dilewati, baris berikutnya tetap terbaca ──
func TestReadJSONLinesOversize(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"url":"a"}` + "\n")
	buf.WriteString(`{"url":"` + strings.Repeat("x", 5000) + `"}` + "\n")
	buf.WriteString(`{"url":"c"}`) // tanpa newline akhir
	var got []string
	skipped, err := readJSONLines(&buf, 1000, func(b []byte) bool { got = append(got, string(b)); return true })
	if err != nil || skipped != 1 || len(got) != 2 || got[1] != `{"url":"c"}` {
		t.Fatalf("skipped=%d err=%v got=%v", skipped, err, got)
	}
	// baris > buffer internal (1MB) tapi < max: utuh
	big := `{"url":"` + strings.Repeat("y", 3<<20) + `"}`
	got = nil
	if _, err := readJSONLines(strings.NewReader(big+"\n"), 8<<20, func(b []byte) bool { got = append(got, string(b)); return true }); err != nil || len(got) != 1 || len(got[0]) != len(big) {
		t.Fatalf("large line broken: err=%v n=%d", err, len(got))
	}
}

// ── -k: normalisasi sama ──
func TestKnownNormalisation(t *testing.T) {
	ks := newKnownSet()
	ks.Add("https://APP.example.com:443/api/one/")
	ks.Add("http://app.example.com/api/two")
	ks.Add("app.example.com/api/three")
	ks.Add("https://app.example.com/api/four [200] [Title]")
	ks.Add("https://app.example.com:8443/api/five")
	for _, u := range []string{"https://app.example.com/api/one", "https://app.example.com/api/two?x=1",
		"https://app.example.com/api/three", "https://app.example.com/api/four", "https://app.example.com:8443/api/five"} {
		if !ks.Contains(u) {
			t.Errorf("known should filter %s", u)
		}
	}
	for _, u := range []string{"https://app.example.com/api/five", "https://app.example.com/api/onex", "https://other.example.com/api/one"} {
		if ks.Contains(u) {
			t.Errorf("known must NOT filter %s", u)
		}
	}
}

func TestScopeArgNormalisation(t *testing.T) {
	for in, want := range map[string]string{"https://*.Example.com:443/x": "example.com", "example.com.": "example.com", "*.a.b.co.id": "a.b.co.id"} {
		if got := normScopeArg(in); got != want {
			t.Errorf("normScopeArg(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBinaryContent(t *testing.T) {
	if !isBinaryContent("image/png", "x") || !isBinaryContent("", "ab\x00cd") {
		t.Error("binary not detected")
	}
	if isBinaryContent("image/svg+xml", "<svg/>") || isBinaryContent("application/javascript", "fetch()") {
		t.Error("text flagged as binary")
	}
}

// ── header -H / -ua terkirim di SEMUA request (termasuk hop redirect) ──
func TestFetchHeadersOnEveryRequest(t *testing.T) {
	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		if r.URL.Path == "/start.js" {
			http.Redirect(w, r, "/final.js", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`fetch("/api/from-fetch-mode");`))
	}))
	defer srv.Close()
	cfg := &Config{Threads: 1, Timeout: 5, UserAgent: "ident-ua/1.0", UAExplicit: true, MaxBodyBytes: 1 << 20, IncludeExternal: true,
		ExtraHeaders: []string{"X-Bug-Bounty: h1-alice", "Cookie: a=1", "Cookie: b=2", "bad header"}}
	if bad := parseHeaders(cfg); len(bad) != 1 {
		t.Fatalf("malformed -H not reported: %v", bad)
	}
	httpClient = buildClient(cfg)
	res := processItem(cfg, WorkItem{URL: srv.URL + "/start.js"}, newKnownSet())
	if len(seen) != 2 {
		t.Fatalf("requests=%d want 2 (redirect)", len(seen))
	}
	for i, h := range seen {
		if h.Get("User-Agent") != "ident-ua/1.0" || h.Get("X-Bug-Bounty") != "h1-alice" || h.Get("Cookie") != "a=1; b=2" {
			t.Errorf("request %d headers: UA=%q X=%q Cookie=%q", i, h.Get("User-Agent"), h.Get("X-Bug-Bounty"), h.Get("Cookie"))
		}
	}
	all := append(res.eps, res.pending...)
	found := false
	for _, e := range all {
		if e.AbsURL == srv.URL+"/api/from-fetch-mode" && strings.HasPrefix(e.Source, srv.URL+"/start.js:") {
			found = true
		}
	}
	if !found {
		t.Errorf("fetch-mode endpoint missing: %+v", all)
	}
}

func TestUAPrecedence(t *testing.T) {
	sess := &FSSession{UserAgent: "fs-ua", Cookies: "cf=1"}
	cfg := &Config{UserAgent: defaultUA}
	r, _ := buildRequest(cfg, "https://x/", sess)
	if r.Header.Get("User-Agent") != "fs-ua" || r.Header.Get("Cookie") != "cf=1" {
		t.Errorf("FS session not applied: %v", r.Header)
	}
	cfg2 := &Config{UserAgent: "mine", UAExplicit: true, ExtraHeaders: []string{"Cookie: id=7", "Host: vhost.internal"}}
	parseHeaders(cfg2)
	r2, _ := buildRequest(cfg2, "https://x/", sess)
	if r2.Header.Get("User-Agent") != "mine" || r2.Header.Get("Cookie") != "cf=1; id=7" || r2.Host != "vhost.internal" {
		t.Errorf("explicit -ua / cookie merge / Host wrong: UA=%q C=%q Host=%q", r2.Header.Get("User-Agent"), r2.Header.Get("Cookie"), r2.Host)
	}
	cfg3 := &Config{UserAgent: "mine", UAExplicit: true, ExtraHeaders: []string{"User-Agent: from-H"}}
	parseHeaders(cfg3)
	r3, _ := buildRequest(cfg3, "https://x/", nil)
	if r3.Header.Get("User-Agent") != "from-H" {
		t.Errorf("-H User-Agent must win: %q", r3.Header.Get("User-Agent"))
	}
}
