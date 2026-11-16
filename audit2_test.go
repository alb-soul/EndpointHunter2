package main

import "testing"

// Regex literal di bundle minified bukan endpoint; `\/` di regex tak di-decode.
func TestRegexLiteralNotPath(t *testing.T) {
	m := ext(t, `if(/Android/i.test(ua)){};s.replace(/%20/g," ");x.match(/a/gim);`+
		`var re=/^application\/pdf$/;var hl={begin:"/},{begin:/",end:1};`+
		`var ok=" see /docs/guide/setup for details";var od="/api/$batch";`)
	for _, bad := range []string{"Android", "%20", "/a/gim", "application/pdf", "begin"} {
		mustNot(t, m, bad)
	}
	mustHave(t, m, "https://app.example.com/docs/guide/setup", "")
	mustHave(t, m, "https://app.example.com/api/$batch", "")
	// `\/` di string literal ber-URL tetap di-decode di JS
	m2 := ext(t, `var c='{"u":"https:\/\/api.example.com\/v9\/items"}';var d="\/api\/esc2";`)
	mustHave(t, m2, "https://api.example.com/v9/items", "")
	mustHave(t, m2, "https://app.example.com/api/esc2", "")
}

// Host dev (localhost) tidak boleh terpilih sbg base lewat voting/deklarasi.
func TestLocalhostNeverBase(t *testing.T) {
	js := `a="http://localhost:80/api/a";b="http://localhost:80/api/b";c="http://localhost:80/api/c";` +
		`d="http://localhost:80/api/d";fetch("/v1/me");var API_BASE="http://localhost:3000";`
	r := Extract(js, ExtractOptions{PageURL: pg, IncludeExternal: true})
	if r.Base != "https://app.example.com" {
		t.Errorf("base = %s", r.Base)
	}
	mustHave(t, epsByURL(r.Endpoints), "https://app.example.com/v1/me", "")
}
