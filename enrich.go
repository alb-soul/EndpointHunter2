package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// fuzzValue is the placeholder injected into fuzzable positions.
const fuzzValue = "FUZZ"

var (
	reEnrichBrace = regexp.MustCompile(`\{[^}]*\}`)
	reEnrichColon = regexp.MustCompile(`:([A-Za-z_]\w*)[+*]?`)
	reEnrichWord  = regexp.MustCompile(`[^A-Za-z0-9_]+`)
)

// Enriched is a fuzz-ready URL plus body param names (populated for non-GET).
type Enriched struct {
	URL  string
	Body []string
}

func isBodyMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

func isJunkVal(s string) bool {
	return strings.Contains(s, "${") || strings.Contains(s, "`")
}

func enrichBraceTokens(s string) []string {
	var toks []string
	for _, g := range reEnrichBrace.FindAllString(s, -1) {
		inner := strings.Trim(g, "{}")
		for _, t := range reEnrichWord.Split(inner, -1) {
			if t != "" {
				toks = append(toks, t)
			}
		}
	}
	return toks
}

// enrichEndpoint injects discovered params into the endpoint as FUZZ.
//   - Path placeholders ({id}, /:id) always become FUZZ.
//   - Empty query values (?x=), JS-template junk (?x=${..}), and {placeholder}
//     query values become FUZZ; concrete values (?service=CSW) are kept.
//   - GET-like methods: leftover params are appended to the query string.
//   - Body methods (POST/PUT/PATCH/DELETE): leftover params go to .Body instead.
func enrichEndpoint(ep Endpoint) Enriched {
	u, err := url.Parse(ep.AbsURL)
	if err != nil {
		return Enriched{URL: applyFuzz(ep.AbsURL)}
	}
	bodyMethod := isBodyMethod(ep.Method)

	covered := map[string]bool{}
	for _, t := range enrichBraceTokens(u.Path) {
		covered[t] = true
	}
	for _, m := range reEnrichColon.FindAllStringSubmatch(u.Path, -1) {
		covered[m[1]] = true
	}

	// fuzz path placeholders ({id} then :id)
	u.Path = reEnrichColon.ReplaceAllString(reEnrichBrace.ReplaceAllString(u.Path, fuzzValue), fuzzValue)
	u.RawPath = "" // force String() to re-encode from the new Path

	// rebuild query, order-preserving
	var pairs [][2]string
	qkeys := map[string]bool{}
	if u.RawQuery != "" {
		for _, seg := range strings.Split(u.RawQuery, "&") {
			if seg == "" {
				continue
			}
			k, v := seg, ""
			if i := strings.Index(seg, "="); i >= 0 {
				k, v = seg[:i], seg[i+1:]
			}
			if k == "" || isJunkVal(k) {
				continue
			}
			for _, t := range enrichBraceTokens(v) {
				covered[t] = true
			}
			if v == "" || isJunkVal(v) || reEnrichBrace.MatchString(v) {
				v = fuzzValue
			}
			pairs = append(pairs, [2]string{k, v})
			qkeys[k] = true
		}
	}

	var body []string
	for _, p := range ep.Params {
		p = strings.TrimSpace(p)
		if p == "" || covered[p] || qkeys[p] {
			continue
		}
		if bodyMethod {
			body = append(body, p)
		} else {
			pairs = append(pairs, [2]string{p, fuzzValue})
			qkeys[p] = true
		}
	}

	var qs []string
	for _, kv := range pairs {
		qs = append(qs, kv[0]+"="+kv[1])
	}
	u.RawQuery = strings.Join(qs, "&")

	out := u.String()
	out = strings.ReplaceAll(out, "%7B", "{")
	out = strings.ReplaceAll(out, "%7D", "}")
	return Enriched{URL: out, Body: body}
}

// buildCurl returns ready-to-run curl command(s) for an endpoint.
// GET/HEAD/OPTIONS -> single GET-style curl with the enriched URL.
// POST/PUT/PATCH/DELETE -> curl -X METHOD with a FUZZ body (json/form/both).
func buildCurl(ep Endpoint, bodyFormat string) []string {
	e := enrichEndpoint(ep)
	method := strings.ToUpper(ep.Method)
	if method == "" {
		method = "GET"
	}
	if !isBodyMethod(method) {
		if method == "GET" {
			return []string{fmt.Sprintf("curl -sk '%s'", e.URL)}
		}
		return []string{fmt.Sprintf("curl -sk -X %s '%s'", method, e.URL)}
	}
	base := fmt.Sprintf("curl -sk -X %s '%s'", method, e.URL)
	if len(e.Body) == 0 {
		return []string{base}
	}
	var out []string
	if bodyFormat == "json" || bodyFormat == "both" {
		var kvs []string
		for _, p := range e.Body {
			kvs = append(kvs, fmt.Sprintf("\"%s\":\"%s\"", p, fuzzValue))
		}
		out = append(out, fmt.Sprintf("%s -H 'Content-Type: application/json' -d '{%s}'", base, strings.Join(kvs, ",")))
	}
	if bodyFormat == "form" || bodyFormat == "both" {
		var kvs []string
		for _, p := range e.Body {
			kvs = append(kvs, p+"="+fuzzValue)
		}
		out = append(out, fmt.Sprintf("%s -d '%s'", base, strings.Join(kvs, "&")))
	}
	return out
}
