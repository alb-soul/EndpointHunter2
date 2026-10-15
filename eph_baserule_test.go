package main

import "testing"

// ── mixed file: page-route tetap page-origin, API-shaped ikut elected base ──
func TestMixedFileBaseRule(t *testing.T) {
	js := "fetch(\"https://api.ep-test.invalid/v1/a\");\n" +
		"fetch(\"https://api.ep-test.invalid/v1/b\");\n" +
		"fetch(\"https://api.ep-test.invalid/v1/c\");\n" +
		"fetch(\"/ep/users\");\n" +
		"fetch(\"/v1/me\");\n" +
		"window.location = \"/ep/logout\";\n"
	eps, base, _ := extractEndpoints(js, "https://h.test/app.js", "https://h.test/app.js", "", false, true)
	// base TERELECT (voter) — tak diubah
	if base != "https://api.ep-test.invalid" {
		t.Fatalf("voter should still elect api base, got %s", base)
	}
	m := epsByURL(eps)
	// page-shape -> page origin
	for _, u := range []string{"https://h.test/ep/users", "https://h.test/ep/logout"} {
		if _, ok := m[u]; !ok {
			t.Errorf("page route misattributed, missing %s", u)
		}
	}
	// api-shape -> elected base
	if _, ok := m["https://api.ep-test.invalid/v1/me"]; !ok {
		t.Errorf("api-shaped relative should follow elected base")
	}
	// explicit baseOverride selalu menang atas keduanya
	eps2, _, _ := extractEndpoints(js, "https://h.test/app.js", "https://h.test/app.js", "https://ovr.test", false, true)
	m2 := epsByURL(eps2)
	for _, u := range []string{"https://ovr.test/ep/users", "https://ovr.test/v1/me"} {
		if _, ok := m2[u]; !ok {
			t.Errorf("explicit base must win, missing %s", u)
		}
	}
}
