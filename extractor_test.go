package main

import (
	"strings"
	"testing"
)

func epsByURL(eps []Endpoint) map[string]Endpoint {
	m := map[string]Endpoint{}
	for _, e := range eps {
		m[e.AbsURL] = e
	}
	return m
}

func TestExtractFamilies(t *testing.T) {
	js := "const a = 1;\n" +
		"fetch(\"/api/users\", {method: \"POST\", body: JSON.stringify({name: \"x\"})});\n" +
		"fetch('https://files.example.com/dl/items?page=2');\n" +
		"axios.get(\"/api/profile\");\n" +
		"axios.post(\"https://files.example.com/v9/orders\", {id: 1});\n" +
		"axios({url: \"/api/search\", method: \"GET\"});\n" +
		"axios({method: \"DELETE\", url: \"/api/item/5\"});\n" +
		"var xhr = new XMLHttpRequest(); xhr.open(\"PUT\", \"/api/upload\");\n" +
		"$.ajax({url: \"/api/legacy\", type: \"GET\"});\n" +
		"$.get(\"/api/ping\");\n" +
		"request.post(\"https://files.example.com/v9/submit\");\n" +
		"router.get(\"/admin/users/:id\", handler);\n" +
		"app.use(\"/api/mw\");\n" +
		"const endpoint = \"/api/v2/orders\";\n" +
		"const tpl = `/api/users/${userId}/orders`;\n" +
		"'https://svc.example.com/lib.js'\n"
	eps, _, _ := extractEndpoints(js, "https://example.com/app.js", "https://example.com/app.js", "", false, true)
	m := epsByURL(eps)
	want := map[string]string{
		"https://example.com/api/users":                 "POST",
		"https://files.example.com/dl/items?page=2":     "GET",
		"https://example.com/api/profile":               "GET",
		"https://files.example.com/v9/orders":           "POST",
		"https://example.com/api/search":                "GET",
		"https://example.com/api/item/5":                "DELETE",
		"https://example.com/api/upload":                "PUT",
		"https://example.com/api/legacy":                "GET",
		"https://example.com/api/ping":                  "GET",
		"https://files.example.com/v9/submit":           "POST",
		"https://example.com/admin/users/:id":           "GET",
		"https://example.com/api/mw":                    "GET",
		"https://example.com/api/v2/orders":             "GET",
		"https://example.com/api/users/{userId}/orders": "GET",
	}
	for u, method := range want {
		e, ok := m[u]
		if !ok {
			t.Errorf("missing endpoint %s", u)
			continue
		}
		if e.Method != method {
			t.Errorf("%s: method=%s want %s", u, e.Method, method)
		}
	}
	// static asset filtered by default
	for u := range m {
		if strings.Contains(u, "cdn.example.com/lib.js") {
			t.Errorf("static asset not filtered: %s", u)
		}
	}
}

func TestBaseResolution(t *testing.T) {
	// pure relative + 1 absolute API URL -> page origin wins (no hijack)
	js := "fetch(\"/api/a\");\nfetch(\"https://api.example.com/v1/only\");\n"
	eps, base, _ := extractEndpoints(js, "https://example.com/a.js", "https://example.com/a.js", "", false, true)
	if base != "https://example.com" {
		t.Fatalf("single absolute URL hijacked base: %s", base)
	}
	found := false
	for _, e := range eps {
		if e.AbsURL == "https://example.com/api/a" {
			found = true
		}
	}
	if !found {
		t.Fatalf("relative endpoint lost")
	}
	// 3 distinct absolute API URLs -> override intended
	js2 := "fetch(\"https://api.example.com/v1/a\");\n" +
		"fetch(\"https://api.example.com/v1/b\");\n" +
		"fetch(\"https://api.example.com/v1/c\");\n" +
		"fetch(\"/v1/me\");\n"
	eps2, base2, _ := extractEndpoints(js2, "https://example.com/a.js", "https://example.com/a.js", "", false, true)
	if base2 != "https://api.example.com" {
		t.Fatalf("strong signal should override base, got %s", base2)
	}
	hit := false
	for _, e := range eps2 {
		if e.AbsURL == "https://api.example.com/v1/me" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("relative endpoint not resolved against overridden base")
	}
}

func TestModernFetchWrappers(t *testing.T) {
	js := "const r1 = await ofetch(\"/api/ofetch-data\");\n" +
		"const r2 = await $fetch(`https://api.example.com/v1/dollar`, {method: 'POST'});\n" +
		"const r3 = await ky.post(\"/api/kything\");\n" +
		"const r4 = await ky.get(\"https://api.example.com/v1/kyget\");\n"
	eps, _, _ := extractEndpoints(js, "https://example.com/a.js", "https://example.com/a.js", "", false, true)
	m := epsByURL(eps)
	for _, u := range []string{
		"https://example.com/api/ofetch-data",
		"https://api.example.com/v1/dollar",
		"https://api.example.com/v1/kyget",
	} {
		if _, ok := m[u]; !ok {
			t.Errorf("missing modern wrapper endpoint %s", u)
		}
	}
}

func TestWebSocketScheme(t *testing.T) {
	js := "const ws = new WebSocket(\"wss://example.com/socket.io/?EIO=4\");\n"
	eps, _, _ := extractEndpoints(js, "https://example.com/a.js", "https://example.com/a.js", "", false, true)
	found := false
	for _, e := range eps {
		if strings.HasPrefix(e.AbsURL, "wss://example.com/socket.io") {
			found = true
		}
	}
	if !found {
		t.Errorf("wss:// endpoint missed")
	}
}

func TestCaseSensitiveDedup(t *testing.T) {
	js := "fetch(\"/API/Users\");\nfetch(\"/api/users\");\n"
	eps, _, _ := extractEndpoints(js, "https://example.com/a.js", "https://example.com/a.js", "", false, true)
	if len(eps) != 2 {
		t.Errorf("case-differing paths merged: got %d want 2", len(eps))
	}
}

func TestExternalSLD(t *testing.T) {
	js := "fetch(\"https://evil.co.uk/api/steal\");\nfetch(\"https://api.example.co.uk/api/ok\");\n"
	eps, _, _ := extractEndpoints(js, "https://example.co.uk/app.js", "https://example.co.uk/app.js", "", false, false)
	m := epsByURL(eps)
	if _, ok := m["https://evil.co.uk/api/steal"]; ok {
		t.Errorf("evil.co.uk kept as same-site (naive SLD)")
	}
	if _, ok := m["https://api.example.co.uk/api/ok"]; !ok {
		t.Errorf("subdomain dropped, should be kept")
	}
}

func TestProtoRelativeScheme(t *testing.T) {
	js := "var endpoint = \"//svc.example.com/lib/api/data\";\n"
	eps, _, _ := extractEndpoints(js, "http://example.com/a.js", "http://example.com/a.js", "", false, true)
	found := false
	for _, e := range eps {
		if strings.HasPrefix(e.AbsURL, "http://svc.example.com/") {
			found = true
		}
		if strings.HasPrefix(e.AbsURL, "https://svc.example.com/") {
			t.Errorf("http base got https: URL: %s", e.AbsURL)
		}
	}
	if !found {
		t.Errorf("protocol-relative URL not resolved")
	}
}

func TestMethodWhitelist(t *testing.T) {
	js := "router.use(\"/api/mw2\");\n"
	eps, _, _ := extractEndpoints(js, "https://example.com/a.js", "https://example.com/a.js", "", false, true)
	for _, e := range eps {
		if e.Method != "GET" && e.Method != "POST" && e.Method != "PUT" && e.Method != "PATCH" && e.Method != "DELETE" && e.Method != "HEAD" && e.Method != "OPTIONS" {
			t.Errorf("non-HTTP method leaked: %s", e.Method)
		}
	}
}

func TestKnownFilterPort(t *testing.T) {
	ks := newKnownSet()
	ks.Add("https://example.com:443/api/known")
	if !ks.Contains("https://example.com/api/known") {
		t.Errorf("same endpoint with/without default port not matched by known filter")
	}
}

func TestEnrichBody(t *testing.T) {
	ep := Endpoint{AbsURL: "https://example.com/api/users/{id}?verbose=", Method: "POST", Params: []string{"name", "verbose", "id"}}
	e := enrichEndpoint(ep)
	if !strings.Contains(e.URL, "/users/FUZZ") {
		t.Errorf("path placeholder not fuzzed: %s", e.URL)
	}
	if len(e.Body) == 0 || e.Body[0] != "name" {
		t.Errorf("body params wrong: %v", e.Body)
	}
	for _, p := range e.Body {
		if p == "id" || p == "verbose" {
			t.Errorf("already-covered param leaked to body: %s", p)
		}
	}
	c := buildCurl(ep, "json")
	if len(c) != 1 || !strings.Contains(c[0], "-X POST") || !strings.Contains(c[0], "application/json") {
		t.Errorf("bad curl: %v", c)
	}
}

func TestScoreInterest(t *testing.T) {
	if scoreInterest("https://x.com/api/admin/users") != "HIGH" {
		t.Errorf("admin should be HIGH")
	}
	if scoreInterest("https://x.com/api/v1/items") != "MED" {
		t.Errorf("api/v1 should be MED")
	}
	if scoreInterest("https://x.com/static/app.js") != "LOW" {
		t.Errorf("static should be LOW")
	}
}

func TestMatchesScopeAndSelfFilter(t *testing.T) {
	if !matchesScope("https://sub.example.com/a", "example.com") {
		t.Errorf("subdomain scope failed")
	}
	if matchesScope("https://example.com.evil.com/a", "example.com") {
		t.Errorf("suffix trick passed scope")
	}
	eps, _, _ := extractEndpoints(
		"fetch(\"https://example.com/app.js\");\nfetch(\"/api/x\");\n",
		"https://example.com/app.js", "https://example.com/app.js", "", false, true)
	for _, e := range eps {
		if e.AbsURL == "https://example.com/app.js" {
			t.Errorf("self URL not filtered")
		}
	}
}

func TestBinusBaseHijack(t *testing.T) {
	// MoreServiceUrl menunjuk halaman frontend (.php) — tidak boleh jadi base.
	// URL API absolut di sibling subdomain harus tetap keluar walau
	// includeExternal=false (base jatuh ke majority-vote api.apps...).
	js := `var MoreServiceUrl="https://acadservices.apps.binus.ac.id/LoginAD.php",` +
		`apiLetterReqToken="https://api.apps.binus.ac.id/letter_request/auth/token",` +
		`apiNotifReportToken="https://api.apps.binus.ac.id/e2es/auth/token",` +
		`apiDSAToken="https://api.apps.binus.ac.id/digital_school/auth/token",` +
		`apiExamToken="https://api.apps.binus.ac.id/exam/status";`
	eps, base, _ := extractEndpoints(js,
		"https://newacadservices.apps.binus.ac.id/assets/app.js",
		"https://newacadservices.apps.binus.ac.id/assets/app.js", "", false, false)
	if strings.Contains(base, "LoginAD") {
		t.Fatalf("base hijacked by frontend page URL: %s", base)
	}
	m := epsByURL(eps)
	for _, u := range []string{
		"https://api.apps.binus.ac.id/letter_request/auth/token",
		"https://api.apps.binus.ac.id/e2es/auth/token",
	} {
		if _, ok := m[u]; !ok {
			t.Errorf("missing endpoint %s (base=%s)", u, base)
		}
	}
}

func TestReorderArgsAfterURL(t *testing.T) {
	got := reorderArgsForParsing([]string{"https://x/y.js", "-o", "out.txt", "-silent"})
	want := []string{"-o", "out.txt", "-silent", "https://x/y.js"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("reorder = %q want %q", got, want)
	}
	got2 := reorderArgsForParsing([]string{"-H", "Cookie: a=b", "https://x/y.js", "--scope", "binus.ac.id"})
	want2 := []string{"-H", "Cookie: a=b", "--scope", "binus.ac.id", "https://x/y.js"}
	if strings.Join(got2, "\x00") != strings.Join(want2, "\x00") {
		t.Fatalf("reorder2 = %q want %q", got2, want2)
	}
	got3 := reorderArgsForParsing([]string{"https://x/y.js", "-oout.txt"})
	want3 := []string{"-o", "out.txt", "https://x/y.js"}
	if strings.Join(got3, "\x00") != strings.Join(want3, "\x00") {
		t.Fatalf("reorder3 = %q want %q", got3, want3)
	}
}

func TestExternalDropCounted(t *testing.T) {
	js := "fetch(\"https://api.other.com/v1/x\");\nfetch(\"/api/local\");\n"
	_, _, skipped := extractEndpoints(js, "https://example.com/a.js", "https://example.com/a.js", "", false, false)
	if skipped != 1 {
		t.Fatalf("skippedExternal = %d want 1", skipped)
	}
	_, _, skipped2 := extractEndpoints(js, "https://example.com/a.js", "https://example.com/a.js", "", false, true)
	if skipped2 != 0 {
		t.Fatalf("skippedExternal with includeExternal = %d want 0", skipped2)
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"api.apps.binus.ac.id":             "binus.ac.id",
		"newacadservices.apps.binus.ac.id": "binus.ac.id",
		"binus.ac.id":                      "binus.ac.id",
		"api.example.co.uk":                "example.co.uk",
		"10.0.0.5":                         "10.0.0.5",
		"example.com:8443":                 "example.com",
		"localhost":                        "localhost",
		"evil.co.id":                       "evil.co.id",
		"target.co.id":                     "target.co.id",
	}
	for in, want := range cases {
		if got := registrableDomain(in); got != want {
			t.Errorf("registrableDomain(%q) = %q want %q", in, got, want)
		}
	}
}

func TestPassScopeFilterModes(t *testing.T) {
	api := "https://api.apps.binus.ac.id/letter_request/auth/token"
	front := "https://acadservices.apps.binus.ac.id/acadservices/x"
	src := "newacadservices.apps.binus.ac.id"
	mk := func() *Config { return &Config{} }

	// default luas
	if !passScopeFilter(mk(), api, "") || !passScopeFilter(mk(), front, "") {
		t.Fatalf("default must keep everything")
	}
	// --scope D (D + turunan)
	c := mk()
	c.Scope = "binus.ac.id"
	if !passScopeFilter(c, api, "") || !passScopeFilter(c, front, "") {
		t.Fatalf("--scope binus.ac.id must keep subdomains")
	}
	if passScopeFilter(c, "https://evil.com/api/x", "") {
		t.Fatalf("--scope must drop out-of-scope")
	}
	// --scope D --scope-exact (tepat D saja)
	c2 := mk()
	c2.Scope, c2.ScopeExact = "binus.ac.id", true
	if !passScopeFilter(c2, "https://binus.ac.id/x", "") {
		t.Fatalf("exact must keep apex")
	}
	if passScopeFilter(c2, api, "") {
		t.Fatalf("exact must drop subdomains")
	}
	// --scope sub --scope-exact (tepat satu host)
	c3 := mk()
	c3.Scope, c3.ScopeExact = "api.apps.binus.ac.id", true
	if !passScopeFilter(c3, api, "") || passScopeFilter(c3, front, "") {
		t.Fatalf("exact subdomain scoping wrong")
	}
	// -bs (regdom sumber)
	c4 := mk()
	c4.BaseScope = true
	if !passScopeFilter(c4, api, src) || !passScopeFilter(c4, front, src) {
		t.Fatalf("-bs must keep same-regdom siblings")
	}
	if passScopeFilter(c4, "https://api.other.id/x", src) {
		t.Fatalf("-bs must drop other regdom")
	}
	// -bs + --scope-exact (tepat host sumber)
	c5 := mk()
	c5.BaseScope, c5.ScopeExact = true, true
	if passScopeFilter(c5, api, src) {
		t.Fatalf("-bs exact must drop sibling (only source host)")
	}
}
