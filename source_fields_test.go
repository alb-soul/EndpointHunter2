package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Bug 2: "source" ambigu untuk host berport -> field terstruktur source_url/line/col
// (string "source" tidak berubah).
func TestJSONLStructuredSource(t *testing.T) {
	r := Extract(demoHTML, ExtractOptions{SourceLabel: demoPage, PageURL: demoPage, ContentType: "text/html", IncludeExternal: true})
	prefix := filepath.Join(t.TempDir(), "new-endpoints")
	cfg := &Config{OutPrefix: prefix, BodyFormat: "json", Silent: true}
	if err := writeMultiStream(cfg, r.Endpoints); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(prefix + ".jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("jsonl lines=%d: %s", len(lines), data)
	}
	for _, l := range lines {
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"url", "method", "interest", "source", "source_url", "line", "col"} {
			if _, ok := rec[k]; !ok {
				t.Errorf("field %q missing: %s", k, l)
			}
		}
		su, _ := rec["source_url"].(string)
		line, _ := rec["line"].(float64)
		col, _ := rec["col"].(float64)
		if su != demoPage {
			t.Errorf("source_url=%q want %q", su, demoPage)
		}
		// string lama tetap persis "<url>:<line>:<col>"
		if want := fmt.Sprintf("%s:%d:%d", demoPage, int(line), int(col)); rec["source"] != want {
			t.Errorf("source=%v want %s", rec["source"], want)
		}
		// line:col menunjuk ke awal URL literal di body asli
		u := strings.TrimPrefix(rec["url"].(string), demoPage)
		lit := u
		if strings.Contains(u, "{userId}") {
			lit = "/api/v1/users/${userId}/sessions"
		}
		off := strings.Index(demoHTML, `"`+lit) + 1
		if off <= 0 {
			off = strings.Index(demoHTML, "`"+lit) + 1
		}
		wl := strings.Count(demoHTML[:off], "\n") + 1
		wc := off - (strings.LastIndex(demoHTML[:off], "\n") + 1) + 1
		if int(line) != wl || int(col) != wc {
			t.Errorf("%s at %d:%d want %d:%d", u, int(line), int(col), wl, wc)
		}
	}
	// field baru omitempty: record tanpa info posisi tidak menulis "line":0
	b, _ := json.Marshal(toResult(Endpoint{AbsURL: "https://x/a", Method: "GET"}, "https://x/a", nil))
	if s := string(b); strings.Contains(s, "source_url") || strings.Contains(s, `"line"`) || strings.Contains(s, `"col"`) {
		t.Errorf("new fields not omitempty: %s", s)
	}
}
