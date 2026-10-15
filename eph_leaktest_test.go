package main

import "testing"

// ── leaktest-2026-10 ronde-1: decode + sink + generic-path + openapi ──
func TestLeaktestEP(t *testing.T) {
	js := "fetch(\"/ep/\"+\"m/config\");\n" +
		"fetch(\"\\x2f\\x65\\x70\\x2f\\x6d\\x2f\\x68\\x65\\x61\\x6c\\x74\\x68\");\n" +
		"fetch([\"https:\",\"\",\"api.ep-test.invalid\",\"m\",\"ping\"].join(\"/\"));\n" +
		"var u=\"https://api.ep-test.invalid\";fetch(u+\"/m/token\");\n" +
		"window.location = \"/ep/logout\";\n" +
		"const MAP = [\"/ep/a/health\", \"/ep/a/version\"];\n" +
		"// TODO: migrate /ep/api/v0/old soon\n"
	eps, _, _ := extractEndpoints(js, "https://h.test/ep/static/x.js", "https://h.test/ep/static/x.js", "", false, true)
	m := epsByURL(eps)
	want := []string{
		"https://h.test/ep/m/config",
		"https://h.test/ep/m/health",
		"https://api.ep-test.invalid/m/ping",
		"https://api.ep-test.invalid/m/token",
		"https://h.test/ep/logout",
		"https://h.test/ep/a/health",
		"https://h.test/ep/a/version",
		"https://h.test/ep/api/v0/old",
	}
	for _, u := range want {
		if _, ok := m[u]; !ok {
			t.Errorf("missing endpoint %s", u)
		}
	}
}

// api.js: const API + concat -> base ter-elect api-host (by design, cermin TestBaseResolution js2)
func TestLeaktestEPAPIClient(t *testing.T) {
	js := "const API = \"https://api.ep-test.invalid\";\n" +
		"fetch(API + \"/v1/profile\");\n" +
		"fetch(`${API}/v1/acme/settings`);\n" +
		"fetch(API + \"/v1/health\");\n" +
		"fetch(\"/v1/me\");\n"
	eps, base, _ := extractEndpoints(js, "https://h.test/ep/static/api.js", "https://h.test/ep/static/api.js", "", false, true)
	if base != "https://api.ep-test.invalid" {
		t.Fatalf("api-client base should elect api host, got %s", base)
	}
	m := epsByURL(eps)
	for _, u := range []string{
		"https://api.ep-test.invalid/v1/profile",
		"https://api.ep-test.invalid/v1/acme/settings",
		"https://api.ep-test.invalid/v1/health",
		"https://api.ep-test.invalid/v1/me",
	} {
		if _, ok := m[u]; !ok {
			t.Errorf("missing endpoint %s", u)
		}
	}
}

func TestLeaktestEPDecoys(t *testing.T) {
	js := "const notUrl = \"/usr/local/bin/ep-tool\";\n" +
		"const frac = \"ratio 3/4 done\";\n" +
		"const v = \"/\";\n"
	eps, _, _ := extractEndpoints(js, "https://h.test/x.js", "https://h.test/x.js", "", false, true)
	m := epsByURL(eps)
	for u := range m {
		t.Errorf("FP decoy fired: %s", u)
	}
}

func TestLeaktestEPOpenAPI(t *testing.T) {
	spec := `{"openapi": "3.0.0", "paths": {` +
		`"/ep/spec/pets": {"get": {}}, ` +
		`"/ep/spec/orders/{oid}": {"post": {}}}}`
	eps, _, _ := extractEndpoints(spec, "https://h.test/ep/openapi.json", "https://h.test/ep/openapi.json", "", false, true)
	m := epsByURL(eps)
	for _, u := range []string{"https://h.test/ep/spec/pets", "https://h.test/ep/spec/orders/{oid}"} {
		if _, ok := m[u]; !ok {
			t.Errorf("missing spec endpoint %s", u)
		}
	}
}
