package main

import (
	"strings"
	"testing"
)

// Inline JS dari target demo recon-dashboard (_fixtures/demo_target.py, host berport).
const demoPage = "http://127.0.0.1:8011"

const demoHTML = `<!doctype html>
<html><head><title>demo</title></head><body>
<h1>demo target</h1>
<script>
  const API = "/api/v1/users";
  const userId = 42;
  fetch(API);
  fetch(` + "`/api/v1/users/${userId}/sessions`" + `, { method: "DELETE" });
  fetch("/graphql", { method: "POST", body: JSON.stringify({ query: "{ me { id } }" }) });
</script>
</body></html>`

func demoEndpoints(t *testing.T) map[string]Endpoint {
	t.Helper()
	r := Extract(demoHTML, ExtractOptions{SourceLabel: demoPage, PageURL: demoPage, ContentType: "text/html", IncludeExternal: true})
	return epsByURL(r.Endpoints)
}

// Bug 1: kunci body JSON tidak boleh disalin ke params.
func TestParamsExcludeBodyKeys(t *testing.T) {
	m := demoEndpoints(t)
	want := []struct {
		url, method  string
		params, body []string
	}{
		{"http://127.0.0.1:8011/api/v1/users", "GET", nil, nil},
		{"http://127.0.0.1:8011/api/v1/users/{userId}/sessions", "DELETE", []string{"userId"}, nil},
		{"http://127.0.0.1:8011/graphql", "POST", nil, []string{"query"}},
	}
	for _, w := range want {
		e := mustHave(t, m, w.url, w.method)
		if strings.Join(e.Params, ",") != strings.Join(w.params, ",") {
			t.Errorf("%s params=%v want %v", w.url, e.Params, w.params)
		}
		if got := enrichEndpoint(e).Body; strings.Join(got, ",") != strings.Join(w.body, ",") {
			t.Errorf("%s body_params=%v want %v", w.url, got, w.body)
		}
	}
	if len(m) != len(want) {
		t.Errorf("got %d endpoints want %d: %v", len(m), len(want), m)
	}
}

// Query string URL + query dari konteks tetap di params; body tetap terpisah.
func TestParamsQueryVsBody(t *testing.T) {
	m := ext(t, `fetch("/api/search?q=1&page=2",{method:"POST",body:JSON.stringify({term:t,limit:5})});`+
		`axios.get("/api/list",{params:{size:10}});`+
		`axios.post("/api/form",{name:n},{params:{dry:1}});`)
	s := mustHave(t, m, "https://app.example.com/api/search?q=1&page=2", "POST")
	if strings.Join(s.Params, ",") != "q,page" || strings.Join(s.BodyKeys, ",") != "term,limit" {
		t.Errorf("search params=%v body=%v", s.Params, s.BodyKeys)
	}
	l := mustHave(t, m, "https://app.example.com/api/list", "GET")
	if strings.Join(l.Params, ",") != "size" || len(l.BodyKeys) != 0 {
		t.Errorf("list params=%v body=%v", l.Params, l.BodyKeys)
	}
	f := mustHave(t, m, "https://app.example.com/api/form", "POST")
	if strings.Join(f.Params, ",") != "dry" || strings.Join(f.BodyKeys, ",") != "name" {
		t.Errorf("form params=%v body=%v", f.Params, f.BodyKeys)
	}
	e := enrichEndpoint(f)
	if !strings.Contains(e.URL, "dry=FUZZ") || strings.Contains(e.URL, "name=") || strings.Join(e.Body, ",") != "name" {
		t.Errorf("enrich form: url=%s body=%v", e.URL, e.Body)
	}
}
