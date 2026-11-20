package main

import "testing"

// Target IPv6 (reconin3/scantarget3 mengirim --scope "::1" untuk [::1]:port).
// Dulu "::1" diperlakukan host:port → ":1" dibuang sbg port → scope ":" →
// SEMUA endpoint target IPv6 terbuang (0 vs 8 pada IPv4 dgn isi sama).

func TestHostOnly(t *testing.T) {
	for in, want := range map[string]string{
		"::1": "::1", "[::1]": "::1", "[::1]:18999": "::1", "2001:db8::1": "2001:db8::1",
		"[2001:db8::1]:443": "2001:db8::1", "example.com:8080": "example.com",
		"example.com": "example.com", "127.0.0.1:80": "127.0.0.1", "host:abc": "host:abc",
	} {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q)=%q want %q", in, got, want)
		}
	}
}

func TestScopeArgIPv6(t *testing.T) {
	for in, want := range map[string]string{
		"::1": "::1", "[::1]": "::1", "[::1]:18999": "::1", "http://[::1]:18999/x": "::1",
		"2001:DB8::1": "2001:db8::1", "[2001:db8::1]": "2001:db8::1", "127.0.0.1:8080": "127.0.0.1",
	} {
		if got := normScopeArg(in); got != want {
			t.Errorf("normScopeArg(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRegistrableDomainIPv6(t *testing.T) {
	for in, want := range map[string]string{
		"::1": "::1", "[::1]:8080": "::1", "2001:db8::1": "2001:db8::1", "[2001:db8::1]": "2001:db8::1",
	} {
		if got := registrableDomain(in); got != want {
			t.Errorf("registrableDomain(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPassScopeIPv6(t *testing.T) {
	cfg := &Config{Scope: normScopeArg("::1")}
	if !passScopeFilter(cfg, "http://[::1]:18999/api/orders", "") {
		t.Error("in-scope IPv6 URL dibuang")
	}
	if passScopeFilter(cfg, "http://[::2]:18999/api/orders", "") {
		t.Error("IPv6 lain lolos scope")
	}
	if passScopeFilter(cfg, "http://evil.com/api", "") {
		t.Error("host lain lolos scope IPv6")
	}
	chk := scopeChecker(cfg, "")
	if chk == nil || !chk("::1") {
		t.Error("scopeChecker menolak host IPv6 (dipakai deteksi base)")
	}
	// -bs: scope dari host sumber IPv6
	cfg2 := &Config{BaseScope: true}
	if !passScopeFilter(cfg2, "http://[::1]:18999/api/x", "::1") {
		t.Error("-bs IPv6 menolak host sendiri")
	}
	if passScopeFilter(cfg2, "http://[2001:db8::2]/api/x", "2001:db8::1") {
		t.Error("-bs IPv6 menerima IP lain")
	}
}

func TestExtractIPv6Page(t *testing.T) {
	page := "http://[::1]:18999/static/app.js"
	body := `fetch("/api/v2/items"); axios.post("/api/orders",{a:1}); fetch(` + "`/api/users/${uid}/profile`" + `);`
	cfg := &Config{Scope: normScopeArg("::1"), IncludeExternal: true}
	r := Extract(body, ExtractOptions{SourceLabel: page, PageURL: page, ContentType: "application/javascript",
		IncludeExternal: true, InScope: scopeChecker(cfg, "")})
	kept := 0
	for _, ep := range r.Endpoints {
		if ep.AbsURL == "" {
			continue
		}
		if passScopeFilter(cfg, ep.AbsURL, "") {
			kept++
		}
		if len(ep.AbsURL) > 0 && ep.AbsURL[:len("http://[::1]:18999/")] != "http://[::1]:18999/" {
			t.Errorf("URL IPv6 rusak: %q", ep.AbsURL)
		}
	}
	if kept < 3 {
		t.Errorf("endpoint IPv6 in-scope = %d, want >=3 (endpoints=%+v)", kept, r.Endpoints)
	}
}
