package main

// ============================================================
// context.go — analisis konteks panggilan/objek di sekitar URL
//
// Method & params diambil HANYA dari argumen panggilan yang memuat URL
// (fetch(url, {method, body}), axios.post(url, data, cfg), $.get(url, data))
// atau dari objek config tempat URL menjadi nilai key (axios({url, method,
// data}), $.ajax({url, type, data})). Dulu: regex body:{...} di jendela ±500
// char -> params panggilan TETANGGA "bocor" ke endpoint ini.
// ============================================================

import "strings"

type argStyle int

const (
	argNone    argStyle = iota
	argOptions          // fetch(url, {method, body, headers, params})
	argAxios            // axios.post(url, data, cfg) / axios.get(url, cfg)
	argJQ               // $.get(url, data)
)

type ctxInfo struct {
	method string
	query  []string
	body   []string
}

type objEntry struct {
	key string
	val string // "" untuk shorthand
}

const ctxLimit = 3000

// matchClose: c[open] adalah ( [ {; return indeks penutup pasangannya (-1 gagal).
func matchClose(c string, open, limit int) int {
	depth := 0
	for i := open; i < len(c) && i < open+limit; i++ {
		switch c[i] {
		case '"', '\'', '`':
			j := skipString(c, i)
			if j < 0 {
				return -1
			}
			i = j
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// skipExpr: maju dari i sampai ',' pada depth 0 atau end (eksklusif).
func skipExpr(s string, i, end int) int {
	depth := 0
	for ; i < end; i++ {
		switch s[i] {
		case '"', '\'', '`':
			j := skipString(s, i)
			if j < 0 || j >= end {
				return end
			}
			i = j
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth < 0 {
				return i
			}
		case ',':
			if depth == 0 {
				return i
			}
		}
	}
	return end
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// objectEntries: entri depth-0 dari literal objek obj ("{...}").
func objectEntries(obj string) []objEntry {
	if len(obj) < 2 || obj[0] != '{' {
		return nil
	}
	end := len(obj) - 1
	var out []objEntry
	i := 1
	for i < end && len(out) < 60 {
		for i < end && (isWSByte(obj[i]) || obj[i] == ',') {
			i++
		}
		if i >= end {
			break
		}
		key := ""
		switch {
		case obj[i] == '"' || obj[i] == '\'':
			j := skipString(obj, i)
			if j < 0 || j >= end {
				return out
			}
			key = obj[i+1 : j]
			i = j + 1
		case strings.HasPrefix(obj[i:], "..."):
			i = skipExpr(obj, i+3, end)
			continue
		case isIdentStart(obj[i]):
			j := i
			for j < end && isIdentByte(obj[j]) {
				j++
			}
			key = obj[i:j]
			i = j
		default:
			i = skipExpr(obj, i, end)
			continue
		}
		for i < end && isWSByte(obj[i]) {
			i++
		}
		switch {
		case i < end && obj[i] == ':':
			ve := skipExpr(obj, i+1, end)
			out = append(out, objEntry{key, strings.TrimSpace(obj[i+1 : ve])})
			i = ve
		case i < end && obj[i] == '(': // method shorthand name(){...}
			i = skipExpr(obj, i, end)
		default:
			if key != "" && (i >= end || obj[i] == ',') {
				out = append(out, objEntry{key, ""})
			}
			i = skipExpr(obj, i, end)
		}
	}
	return out
}

// objectLiteralOf: nilai -> literal objek di dalamnya (JSON.stringify({..}),
// new URLSearchParams({..}), qs.stringify({..})).
func objectLiteralOf(v string) string {
	v = strings.TrimSpace(v)
	for _, p := range []string{"JSON.stringify(", "new URLSearchParams(", "qs.stringify(", "Qs.stringify(", "stringify("} {
		if strings.HasPrefix(v, p) {
			v = strings.TrimSpace(v[len(p):])
			break
		}
	}
	if !strings.HasPrefix(v, "{") {
		return ""
	}
	cl := matchClose(v, 0, len(v))
	if cl < 0 {
		return ""
	}
	return v[:cl+1]
}

func keysOf(obj string) []string {
	var ks []string
	for _, e := range objectEntries(obj) {
		k := e.key
		if k == "" || len(k) > 40 || strings.ContainsAny(k, " /{}") {
			continue
		}
		ks = append(ks, k)
	}
	return ks
}

func litValue(v string) string {
	if s, ok := unquoteLit(strings.TrimSpace(v)); ok {
		return s
	}
	return ""
}

// readConfigObject: method/type, body (body/data/json/payload/variables/form)
// dan query (params/query/searchParams) dari entri depth-0 sebuah objek.
func readConfigObject(obj string, ci *ctxInfo, withMethod bool) {
	for _, e := range objectEntries(obj) {
		switch strings.ToLower(e.key) {
		case "method", "type", "verb", "httpmethod":
			if withMethod {
				if m := strings.ToUpper(litValue(e.val)); validHTTPMethod(m) {
					ci.method = m
				}
			}
		case "body", "data", "json", "payload", "variables", "form", "formdata":
			if o := objectLiteralOf(e.val); o != "" {
				ci.body = append(ci.body, keysOf(o)...)
			}
		case "params", "query", "searchparams", "qs":
			if o := objectLiteralOf(e.val); o != "" {
				ci.query = append(ci.query, keysOf(o)...)
			}
		}
	}
}

// callOpenBefore: q = indeks quote pembuka literal URL. Bila literal adalah
// argumen pertama sebuah panggilan (opsional didahului `IDENT +`), return
// indeks '(' panggilan itu; else -1.
func callOpenBefore(c string, q int) int {
	i := q - 1
	for i >= 0 && isWSByte(c[i]) {
		i--
	}
	if i >= 0 && c[i] == '+' {
		i--
		for i >= 0 && isWSByte(c[i]) {
			i--
		}
		j := i
		for j >= 0 && (isIdentByte(c[j]) || c[j] == '.') {
			j--
		}
		if j == i {
			return -1
		}
		i = j
		for i >= 0 && isWSByte(c[i]) {
			i--
		}
	}
	if i < 0 || c[i] != '(' {
		return -1
	}
	k := i - 1
	for k >= 0 && isWSByte(c[k]) {
		k--
	}
	if k >= 0 && (isIdentByte(c[k]) || c[k] == ')' || c[k] == ']' || c[k] == '>') {
		// bukan kata kunci kontrol (if(/while(/switch( ...)
		j := k
		for j >= 0 && isIdentByte(c[j]) {
			j--
		}
		switch c[j+1 : k+1] {
		case "if", "while", "switch", "for", "return", "typeof", "catch", "with":
			return -1
		}
		return i
	}
	return -1
}

// enclosingObject: '{' objek yang memuat literal di q sebagai nilai depth-0.
func enclosingObject(c string, q int) int {
	depth := 0
	for i := q - 1; i >= 0 && i > q-1500; i-- {
		switch c[i] {
		case '}', ')', ']':
			depth++
		case '{':
			if depth == 0 {
				return i
			}
			depth--
		case '(', '[':
			if depth == 0 {
				return -1
			}
			depth--
		case ';':
			if depth == 0 {
				return -1
			}
		}
	}
	return -1
}

// analyzeCall: konteks argumen panggilan yang '(' -nya di open.
// method = method dari pola (boleh ""), dipakai menentukan arti argumen axios.
func analyzeCall(c string, open int, style argStyle, method string) ctxInfo {
	var ci ctxInfo
	args, _, ok := splitTopArgs(c, open)
	if !ok || len(args) < 2 {
		return ci
	}
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch style {
	case argOptions:
		if o := objectLiteralOf(arg(1)); o != "" {
			readConfigObject(o, &ci, true)
		}
	case argAxios:
		if isBodyMethod(method) {
			if o := objectLiteralOf(arg(1)); o != "" {
				ci.body = append(ci.body, keysOf(o)...)
			}
			if o := objectLiteralOf(arg(2)); o != "" {
				readConfigObject(o, &ci, false)
			}
		} else if o := objectLiteralOf(arg(1)); o != "" {
			readConfigObject(o, &ci, false)
		}
	case argJQ:
		if o := objectLiteralOf(arg(1)); o != "" {
			if isBodyMethod(method) {
				ci.body = append(ci.body, keysOf(o)...)
			} else {
				ci.query = append(ci.query, keysOf(o)...)
			}
		}
	}
	return ci
}

// analyzeObject: konteks objek config yang memuat URL (di q) sbg nilai.
func analyzeObject(c string, q int) ctxInfo {
	var ci ctxInfo
	open := enclosingObject(c, q)
	if open < 0 {
		return ci
	}
	cl := matchClose(c, open, ctxLimit)
	if cl < 0 {
		return ci
	}
	readConfigObject(c[open:cl+1], &ci, true)
	return ci
}
