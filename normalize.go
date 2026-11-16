package main

// ============================================================
// normalize.go — pra-ekstraksi (decode / join / propagate / rekonstruksi route)
//
// Semua transformasi mencatat peta posisi sehingga temuan pada konten
// ternormalisasi dipetakan balik ke offset ASLI -> source "file:line:col"
// tetap akurat walau konten di-decode / digabung (dulu: nomor baris bergeser
// saat "a"+\n"b" digabung, \u000a di-decode jadi newline, dst).
//
// Performa: tidak ada regex yang di-scan ke seluruh konten tanpa prefix
// literal; kandidat dicari manual (IndexByte/Index) lalu regex ter-anchor.
// ============================================================

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ─── Peta posisi ────────────────────────────────────────────────────────────

// span: potongan output mulai n (offset baru) berasal dari offset lama o.
// verb=true -> salinan verbatim (offset di dalamnya bergeser linear);
// verb=false -> teks pengganti (semua offset di dalamnya -> o).
type span struct {
	n, o int
	verb bool
}

type posMap []span

// mapper: peta offset baru -> offset lama (posMap tunggal atau rantai).
type mapper interface{ old(p int) int }

// posChain: komposisi beberapa peta (diterapkan dari belakang).
type posChain []mapper

func (c posChain) old(p int) int {
	for i := len(c) - 1; i >= 0; i-- {
		p = c[i].old(p)
	}
	return p
}

// asMapper: hindari typed-nil di interface.
func asMapper(m posMap) mapper {
	if m == nil {
		return nil
	}
	return m
}

func (m posMap) old(p int) int {
	i := sort.Search(len(m), func(i int) bool { return m[i].n > p }) - 1
	if i < 0 {
		return p
	}
	if m[i].verb {
		return m[i].o + (p - m[i].n)
	}
	return m[i].o
}

type tbuild struct {
	b strings.Builder
	m posMap
}

func (t *tbuild) keep(src string, from, to int) {
	if from >= to {
		return
	}
	t.m = append(t.m, span{t.b.Len(), from, true})
	t.b.WriteString(src[from:to])
}

func (t *tbuild) put(oldPos int, s string) {
	t.m = append(t.m, span{t.b.Len(), oldPos, false})
	t.b.WriteString(s)
}

// replaceLocs: ganti match (locs terurut, tak tumpang-tindih) via fn.
func replaceLocs(s string, locs [][]int, fn func(loc []int) (string, bool)) (string, mapper) {
	if len(locs) == 0 {
		return s, nil
	}
	var t tbuild
	prev := 0
	changed := false
	for _, loc := range locs {
		if loc[0] < prev {
			continue
		}
		rep, ok := fn(loc)
		if !ok || rep == s[loc[0]:loc[1]] {
			continue
		}
		if !changed {
			t.b.Grow(len(s))
		}
		t.keep(s, prev, loc[0])
		t.put(loc[0], rep)
		prev = loc[1]
		changed = true
	}
	if !changed {
		return s, nil
	}
	t.keep(s, prev, len(s))
	return t.b.String(), asMapper(t.m)
}

// replaceTracked: ReplaceAllStringFunc + peta posisi (regex dgn prefix literal).
func replaceTracked(s string, re *regexp.Regexp, fn func(loc []int) (string, bool)) (string, mapper) {
	return replaceLocs(s, re.FindAllStringSubmatchIndex(s, -1), fn)
}

// normText: konten + rantai peta posisi ke konten asli.
type normText struct {
	s    string
	maps []mapper
}

func (nt *normText) apply(f func(string) (string, mapper)) bool {
	n, m := f(nt.s)
	if m == nil {
		return false
	}
	nt.s = n
	nt.maps = append(nt.maps, m)
	return true
}

// orig: offset di konten ternormalisasi -> offset di konten asli.
func (nt *normText) orig(p int) int { return posChain(nt.maps).old(p) }

// result: hasil transformasi berulang sbg satu mapper (nil bila tak berubah).
func (nt *normText) result(orig string) (string, mapper) {
	if len(nt.maps) == 0 {
		return orig, nil
	}
	return nt.s, posChain(nt.maps)
}

// ─── Decode ──────────────────────────────────────────────────────────────────

var (
	reEscSeqEP     = regexp.MustCompile(`\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\}|/)`)
	reHTMLEntityEP = regexp.MustCompile(`&(?:quot|amp|apos|#0*39|#[xX]0*27|#0*34|#[xX]0*22|#[xX]0*2[fF]|#0*47|#[xX]0*3[aAdDfF]|#0*58|#0*61|#0*63);`)
)

// unsafeDecoded: karakter yang TIDAK boleh hasil decode karena mengubah
// struktur sintaks (memecah/menutup string literal, menambah baris, escape).
// Dulu escape-u-0022 didecode jadi tanda kutip -> string terpotong dan memunculkan FP;
// "\u000a" jadi newline -> nomor baris bergeser.
func unsafeDecoded(r rune) bool {
	return r < 0x20 || r == 0x7f || r == '"' || r == '\'' || r == '`' || r == '\\' ||
		(r >= 0xD800 && r <= 0xDFFF) || r > 0x10FFFF
}

// decodeEscapesEP: \xHH, \uHHHH, \u{H..} dan \/ (JSON gaya PHP) -> karakter,
// kecuali karakter struktural (lihat unsafeDecoded).
func decodeEscapesEP(s string) (string, mapper) {
	return decodeEscapesWith(s, nil)
}

// decodeEscapesJS: seperti decodeEscapesEP, tetapi `\/` hanya di-decode di
// dalam string literal ber-URL ("\/api\/x", "https:\/\/h\/p"). Di JS, `\/`
// paling sering ada di REGEX literal (/^application\/pdf$/) — men-decode-nya
// mengubah regex jadi "path" palsu.
func decodeEscapesJS(s string) (string, mapper) {
	if !strings.Contains(s, `\/`) {
		return decodeEscapesWith(s, func(int) bool { return false })
	}
	rng := slashyLiteralRanges(s)
	return decodeEscapesWith(s, func(p int) bool {
		i := sort.Search(len(rng), func(i int) bool { return rng[i][1] > p })
		return i < len(rng) && rng[i][0] < p
	})
}

// slashyLiteralRanges: [awal,akhir] string literal yang memuat URL ber-escape
// (diawali "\/ atau memuat :\/\/), terurut & tak tumpang-tindih.
func slashyLiteralRanges(s string) [][2]int {
	var out [][2]int
	add := func(q int) {
		if q >= 0 && q < len(s) {
			if e := skipString(s, q); e > q {
				out = append(out, [2]int{q, e})
			}
		}
	}
	for _, a := range []string{`"\/`, `'\/`} {
		for i := 0; ; {
			k := strings.Index(s[i:], a)
			if k < 0 {
				break
			}
			add(i + k)
			i += k + 1
		}
	}
	for i := 0; ; {
		k := strings.Index(s[i:], `:\/\/`)
		if k < 0 {
			break
		}
		p := i + k
		i = p + 1
		for j := p - 1; j >= 0 && j >= p-12; j-- {
			if s[j] == '"' || s[j] == '\'' {
				add(j)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	w := 0
	for _, r := range out {
		if w > 0 && r[0] <= out[w-1][1] {
			if r[1] > out[w-1][1] {
				out[w-1][1] = r[1]
			}
			continue
		}
		out[w] = r
		w++
	}
	return out[:w]
}

// decodeEscapesWith: slashOK(pos)=false -> `\/` di pos dibiarkan (nil = selalu decode).
func decodeEscapesWith(s string, slashOK func(int) bool) (string, mapper) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	return replaceTracked(s, reEscSeqEP, func(loc []int) (string, bool) {
		if loc[0] > 0 && s[loc[0]-1] == '\\' {
			return "", false // `\\x41` / `\\/` = backslash literal, bukan escape
		}
		if loc[1]-loc[0] == 2 { // `\/`
			if slashOK != nil && !slashOK(loc[0]) {
				return "", false
			}
			return "/", true
		}
		var hex string
		for g := 1; g <= 3; g++ {
			if loc[2*g] >= 0 {
				hex = s[loc[2*g]:loc[2*g+1]]
				break
			}
		}
		v, err := strconv.ParseUint(hex, 16, 32)
		if err != nil || unsafeDecoded(rune(v)) {
			return "", false
		}
		return string(rune(v)), true
	})
}

var htmlEntityVal = map[string]string{
	"quot": `"`, "amp": "&", "apos": "'", "39": "'", "27": "'", "34": `"`, "22": `"`,
	"2f": "/", "47": "/", "3a": ":", "58": ":", "3d": "=", "61": "=", "3f": "?", "63": "?",
}

// decodeHTMLEntitiesEP: entity umum di atribut HTML (data-config="{&quot;...",
// href="/x?a=1&amp;b=2"). Hanya untuk record HTML.
func decodeHTMLEntitiesEP(s string) (string, mapper) {
	if !strings.Contains(s, "&") {
		return s, nil
	}
	return replaceTracked(s, reHTMLEntityEP, func(loc []int) (string, bool) {
		k := strings.ToLower(strings.TrimSuffix(s[loc[0]+1:loc[1]], ";"))
		k = strings.TrimPrefix(k, "#")
		k = strings.TrimPrefix(k, "x")
		k = strings.TrimLeft(k, "0")
		v, ok := htmlEntityVal[k]
		return v, ok
	})
}

// ─── Join literal ────────────────────────────────────────────────────────────

var (
	reConcatLitEP = regexp.MustCompile(`^(?:"([^"\\\n]*)"\s*\+\s*"([^"\\\n]*)"|'([^'\\\n]*)'\s*\+\s*'([^'\\\n]*)')`)
	reArrJoinEP   = regexp.MustCompile(`\[((?:"[^"\\\n]*"|'[^'\\\n]*')(?:\s*,\s*(?:"[^"\\\n]*"|'[^'\\\n]*'))*)\]\.join\(\s*(?:"/"|'/'|""|'')\s*\)`)
	reQuotedEP    = regexp.MustCompile(`"([^"\\\n]*)"|'([^'\\\n]*)'`)
)

// litStartsBeforePlus: awal literal string ("..." / '...') yang langsung
// diikuti `+` (kandidat concat). Dicari dari tiap '+' mundur ke quote.
func litStartsBeforePlus(s string) []int {
	var out []int
	for i := 0; ; {
		k := strings.IndexByte(s[i:], '+')
		if k < 0 {
			break
		}
		p := i + k
		i = p + 1
		j := p - 1
		for j >= 0 && isWSByte(s[j]) {
			j--
		}
		if j < 1 || (s[j] != '"' && s[j] != '\'') {
			continue
		}
		q := s[j]
		for a := j - 1; a >= 0 && a >= j-2000; a-- {
			c := s[a]
			if c == '\n' || c == '\\' {
				break
			}
			if c == q {
				out = append(out, a)
				break
			}
		}
	}
	return out // naik (urut posisi '+')
}

// joinConcatEP: "a" + "b" -> "ab" (berantai, sampai stabil).
func joinConcatEP(s string) (string, mapper) {
	if !strings.Contains(s, "+") {
		return s, nil
	}
	nt := normText{s: s}
	for i := 0; i < 6; i++ {
		if !nt.apply(func(cur string) (string, mapper) {
			locs := anchoredFind(cur, reConcatLitEP, litStartsBeforePlus(cur), 1600, nil)
			return replaceLocs(cur, locs, func(loc []int) (string, bool) {
				if loc[2] >= 0 {
					return `"` + cur[loc[2]:loc[3]] + cur[loc[4]:loc[5]] + `"`, true
				}
				return `'` + cur[loc[6]:loc[7]] + cur[loc[8]:loc[9]] + `'`, true
			})
		}) {
			break
		}
	}
	return nt.result(s)
}

// evalArrJoinEP: ["https:","","h","p"].join("/") -> "https://h/p".
func evalArrJoinEP(s string) (string, mapper) {
	if !strings.Contains(s, "].join(") {
		return s, nil
	}
	// kandidat: '[' terdekat sebelum tiap "].join(" (regex ter-anchor di sana)
	var starts []int
	for i := 0; ; {
		k := strings.Index(s[i:], "].join(")
		if k < 0 {
			break
		}
		p := i + k
		i = p + 1
		if b := strings.LastIndexByte(s[max(0, p-3000):p], '['); b >= 0 {
			starts = append(starts, max(0, p-3000)+b)
		}
	}
	re := reArrJoinAnch
	return replaceLocs(s, anchoredFind(s, re, starts, 3200, nil), func(loc []int) (string, bool) {
		m := s[loc[0]:loc[1]]
		ji := strings.LastIndex(m, ".join(")
		tail := m[ji+len(".join("):]
		sep := ""
		if len(tail) >= 2 && (tail[0] == '"' || tail[0] == '\'') {
			end := strings.IndexByte(tail[1:], tail[0])
			if end < 0 {
				return "", false
			}
			sep = tail[1 : 1+end]
		}
		inner := s[loc[2]:loc[3]]
		var elems []string
		for _, p := range reQuotedEP.FindAllStringSubmatch(inner, -1) {
			if strings.HasPrefix(p[0], `"`) {
				elems = append(elems, p[1])
			} else {
				elems = append(elems, p[2])
			}
		}
		if len(elems) == 0 {
			return "", false
		}
		return `"` + strings.Join(elems, sep) + `"`, true
	})
}

var reArrJoinAnch = regexp.MustCompile(`^(?:` + reArrJoinEP.String() + `)`)

// ─── Propagasi konstanta (linear) ────────────────────────────────────────────

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isWSByte(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// collectVarLits: `var|let|const NAME = "lit"` dan `,NAME="lit"` (deklarator
// koma minified). Dulu regex tanpa prefix ke seluruh konten (lambat).
func collectVarLits(s string) map[string]string {
	out := map[string]string{}
	n := len(s)
	for i := 0; ; {
		k := strings.IndexByte(s[i:], '=')
		if k < 0 {
			break
		}
		p := i + k
		i = p + 1
		if p+1 < n && (s[p+1] == '=' || s[p+1] == '>') {
			continue
		}
		if p > 0 && strings.IndexByte("=!<>+-*/%&|^?", s[p-1]) >= 0 {
			continue
		}
		j := p + 1
		for j < n && isWSByte(s[j]) {
			j++
		}
		if j >= n || (s[j] != '"' && s[j] != '\'') {
			continue
		}
		q := s[j]
		e := j + 1
		for e < n && e-j <= 201 && s[e] != q && s[e] != '\\' && s[e] != '\n' {
			e++
		}
		if e >= n || s[e] != q || e-j-1 < 2 || e-j-1 > 200 {
			continue
		}
		a := p - 1
		for a >= 0 && isWSByte(s[a]) {
			a--
		}
		b := a
		for b >= 0 && isIdentByte(s[b]) {
			b--
		}
		if b == a || !isIdentStart(s[b+1]) {
			continue
		}
		name := s[b+1 : a+1]
		d := b
		for d >= 0 && isWSByte(s[d]) {
			d--
		}
		ok := d >= 0 && s[d] == ','
		if !ok && d < b {
			for _, kw := range [...]string{"var", "let", "const"} {
				st := d + 1 - len(kw)
				if st >= 0 && s[st:d+1] == kw && (st == 0 || !isIdentByte(s[st-1])) {
					ok = true
					break
				}
			}
		}
		if !ok {
			continue
		}
		if _, dup := out[name]; !dup {
			out[name] = s[j : e+1]
		}
	}
	return out
}

// collectShadowed: nama (dari want) yang juga diikat sebagai parameter fungsi/
// arrow/method, nama function/class, variabel loop/catch, atau import ->
// propagasi tidak aman. Dulu 7 regex DI-COMPILE & di-scan ke seluruh konten
// PER deklarasi -> O(decl x size) (bundle 10MB dgn ribuan var = puluhan menit).
func collectShadowed(s string, want map[string]bool) map[string]bool {
	out := map[string]bool{}
	n := len(s)
	mark := func(seg string) {
		for i := 0; i < len(seg); {
			if !isIdentStart(seg[i]) || (i > 0 && isIdentByte(seg[i-1])) {
				i++
				continue
			}
			j := i + 1
			for j < len(seg) && isIdentByte(seg[j]) {
				j++
			}
			if want[seg[i:j]] {
				out[seg[i:j]] = true
			}
			i = j
		}
	}
	skipWS := func(i int) int {
		for i < n && isWSByte(s[i]) {
			i++
		}
		return i
	}
	ident := func(i int) (string, int) {
		j := i
		for j < n && isIdentByte(s[j]) {
			j++
		}
		return s[i:j], j
	}
	// '(' pembuka untuk ')' di close (tanpa kurung bersarang, maks 300)
	openOf := func(close int) int {
		for a := close - 1; a >= 0 && a > close-300; a-- {
			switch s[a] {
			case '(':
				return a
			case ')':
				return -1
			}
		}
		return -1
	}
	eachWord := func(w string, fn func(after int)) {
		for i := 0; ; {
			k := strings.Index(s[i:], w)
			if k < 0 {
				return
			}
			p := i + k
			i = p + 1
			if (p > 0 && isIdentByte(s[p-1])) || (p+len(w) < n && isIdentByte(s[p+len(w)])) {
				continue
			}
			fn(p + len(w))
		}
	}
	eachWord("function", func(a int) {
		a = skipWS(a)
		if a < n && s[a] == '*' {
			a = skipWS(a + 1)
		}
		name, a := ident(a)
		mark(name)
		a = skipWS(a)
		if a < n && s[a] == '(' {
			if c := strings.IndexByte(s[a:min(n, a+300)], ')'); c > 0 {
				mark(s[a+1 : a+c])
			}
		}
	})
	eachWord("class", func(a int) { name, _ := ident(skipWS(a)); mark(name) })
	for _, kw := range [...]string{"for", "catch"} {
		eachWord(kw, func(a int) {
			a = skipWS(a)
			if a >= n || s[a] != '(' {
				return
			}
			a = skipWS(a + 1)
			name, b := ident(a)
			if name == "var" || name == "let" || name == "const" {
				name, _ = ident(skipWS(b))
			}
			mark(name)
		})
	}
	eachWord("import", func(a int) {
		end := min(n, a+300)
		if f := strings.Index(s[a:end], "from"); f > 0 {
			mark(s[a : a+f])
		}
	})
	// arrow: (a,b)=> / a=>
	for i := 0; ; {
		k := strings.Index(s[i:], "=>")
		if k < 0 {
			break
		}
		p := i + k
		i = p + 2
		j := p - 1
		for j >= 0 && isWSByte(s[j]) {
			j--
		}
		if j < 0 {
			continue
		}
		if s[j] == ')' {
			if o := openOf(j); o >= 0 {
				mark(s[o+1 : j])
			}
			continue
		}
		b := j
		for b >= 0 && isIdentByte(s[b]) {
			b--
		}
		mark(s[b+1 : j+1])
	}
	// method shorthand / function body: name(a,b){  (juga if(x){ -> konservatif)
	for i := 0; ; {
		k := strings.IndexByte(s[i:], ')')
		if k < 0 {
			break
		}
		p := i + k
		i = p + 1
		j := skipWS(p + 1)
		if j >= n || s[j] != '{' {
			continue
		}
		if o := openOf(p); o >= 0 {
			mark(s[o+1 : p])
		}
	}
	return out
}

// propagateEP: one-hop constant propagation.
// `var/let/const NAME="lit"` / `,NAME="lit"` dengan TEPAT SATU assignment ->
// use di posisi-nilai (+ ${NAME}) di-inline. Guard: shadowing, reassignment
// (=, op=, ++/--), shorthand {n}, key n:, akses properti .n.
func propagateEP(s string) (string, mapper) {
	if !(strings.Contains(s, "var ") || strings.Contains(s, "let ") || strings.Contains(s, "const ") || strings.Contains(s, ",")) {
		return s, nil
	}
	lits := collectVarLits(s)
	if len(lits) == 0 {
		return s, nil
	}
	want := make(map[string]bool, len(lits))
	for n := range lits {
		want[n] = true
	}
	for n := range collectShadowed(s, want) {
		delete(lits, n)
	}
	if len(lits) == 0 {
		return s, nil
	}

	type occ struct{ a, b int }
	uses := map[string][]occ{}
	assigns := map[string]int{}
	n := len(s)
	for i := 0; i < n; {
		c := s[i]
		if !isIdentStart(c) {
			i++
			continue
		}
		j := i + 1
		for j < n && isIdentByte(s[j]) {
			j++
		}
		if i > 0 && (isIdentByte(s[i-1]) || s[i-1] == '.') {
			i = j
			continue
		}
		name := s[i:j]
		if _, ok := lits[name]; ok {
			k := j
			for k < n && isWSByte(s[k]) {
				k++
			}
			isAssign := false
			if k < n {
				switch {
				case s[k] == '=' && (k+1 >= n || (s[k+1] != '=' && s[k+1] != '>')):
					isAssign = true
				case k+1 < n && s[k+1] == '=' && strings.IndexByte("+-*/%&|^", s[k]) >= 0:
					isAssign = true
				case k+1 < n && ((s[k] == '+' && s[k+1] == '+') || (s[k] == '-' && s[k+1] == '-')):
					isAssign = true
				case k+2 < n && s[k+2] == '=' && (s[k:k+2] == "||" || s[k:k+2] == "&&" || s[k:k+2] == "??"):
					isAssign = true
				}
			}
			if i >= 2 && (s[i-2:i] == "++" || s[i-2:i] == "--") {
				isAssign = true
			}
			if isAssign {
				assigns[name]++
			} else {
				uses[name] = append(uses[name], occ{i, j})
			}
		}
		i = j
	}

	type rep struct {
		a, b int
		text string
	}
	var reps []rep
	for name, lit := range lits {
		if assigns[name] != 1 {
			continue
		}
		for _, u := range uses[name] {
			if u.a >= 2 && s[u.a-2] == '$' && s[u.a-1] == '{' {
				if u.b < n && s[u.b] == '}' {
					// ${NAME} -> nilai telanjang tanpa ${ } dan tanpa quote
					reps = append(reps, rep{u.a - 2, u.b + 1, lit[1 : len(lit)-1]})
				}
				continue
			}
			pi := u.a - 1
			for pi >= 0 && isWSByte(s[pi]) {
				pi--
			}
			ni := u.b
			for ni < n && isWSByte(s[ni]) {
				ni++
			}
			if pi < 0 {
				continue
			}
			pc := s[pi]
			ok := false
			if ni < n {
				nextIsKey := s[ni] == ':' || s[ni] == '=' || s[ni] == '('
				if strings.IndexByte(":=([!;?|&,{", pc) >= 0 && !nextIsKey {
					ok = true
					if (pc == ',' || pc == '{') && !inArrCtx(s, pi) {
						ok = false // shorthand {n} / {a,n}
					}
					if pc == '?' && s[ni] == '.' {
						ok = false
					}
				}
			} else if strings.IndexByte(":=([!;?|&", pc) >= 0 {
				ok = true
			}
			if ok {
				reps = append(reps, rep{u.a, u.b, lit})
			}
		}
	}
	if len(reps) == 0 {
		return s, nil
	}
	sort.Slice(reps, func(i, j int) bool { return reps[i].a < reps[j].a })
	var t tbuild
	t.b.Grow(len(s) + len(reps)*16)
	prev := 0
	for _, r := range reps {
		if r.a < prev {
			continue
		}
		t.keep(s, prev, r.a)
		t.put(r.a, r.text)
		prev = r.b
	}
	t.keep(s, prev, len(s))
	return t.b.String(), asMapper(t.m)
}

// inArrCtx: posisi koma/kurawal dibuka oleh [ atau ( (bukan { object).
func inArrCtx(s string, pos int) bool {
	depth := 0
	for j := pos; j >= 0 && j > pos-80; j-- {
		switch s[j] {
		case '}', ']', ')':
			depth++
		case '{':
			if depth == 0 {
				return false
			}
			depth--
		case '[', '(':
			if depth == 0 {
				return true
			}
			depth--
		}
	}
	return false
}

// ─── Rekonstruksi route dari ekspresi dinamis ───────────────────────────────

var (
	// "lit" + expr [+ "lit2"]   (ter-anchor di awal literal)
	rePlusConcatEP = regexp.MustCompile(`^(["'])((?:/|\./|\.\./|https?://|wss?://)[^"'\\\n]*)(["'])\s*\+\s*([A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*(?:\s*\([^()"'\x60]{0,60}\))?)(?:\s*\+\s*(["'])([^"'\\\n]*)(["']))?`)
	// "lit".concat(  (Babel/TS: template literal -> .concat())
	reDotConcatEP = regexp.MustCompile(`^(?:"[^"\\\n]*"|'[^'\\\n]*')\.concat\(`)
	// ${expr} di template literal
	reTplExprEP = regexp.MustCompile(`\$\{([^{}\x60]{0,160})\}`)
	reStrLitEP  = regexp.MustCompile(`"[^"\\\n]*"|'[^'\\\n]*'`)
	reIdentEP   = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
)

// lastIdent: nama placeholder dari ekspresi ("a.b.id" -> id, encodeURIComponent(n) -> n).
func lastIdent(expr string) string {
	expr = reStrLitEP.ReplaceAllString(expr, "")
	ids := reIdentEP.FindAllString(expr, -1)
	for i := len(ids) - 1; i >= 0; i-- {
		switch ids[i] {
		case "this", "encodeURIComponent", "encodeURI", "String", "toString", "trim", "window", "null", "undefined", "true", "false":
			continue
		}
		return ids[i]
	}
	return "param"
}

// pathy: literal bagian URL (diawali /, ./, ../, skema web).
func pathy(lit string) bool {
	return strings.HasPrefix(lit, "/") || strings.HasPrefix(lit, "./") || strings.HasPrefix(lit, "../") ||
		strings.HasPrefix(lit, "http://") || strings.HasPrefix(lit, "https://") ||
		strings.HasPrefix(lit, "ws://") || strings.HasPrefix(lit, "wss://")
}

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// dropLeadingPlaceholder: "{BASE}/api/x" -> "/api/x" (base tak diketahui:
// lebih baik relatif-ke-origin daripada "{BASE}" ditempel sebagai segmen path).
func dropLeadingPlaceholder(s string) string {
	if strings.HasPrefix(s, "{") {
		if i := strings.IndexByte(s, '}'); i > 0 && i+1 < len(s) && s[i+1] == '/' {
			return s[i+1:]
		}
	}
	return s
}

// plusConcatEP: "/api/user/" + id + "/profile" -> "/api/user/{id}/profile".
func plusConcatEP(s string) (string, mapper) {
	if !strings.Contains(s, "+") {
		return s, nil
	}
	nt := normText{s: s}
	for i := 0; i < 6; i++ {
		if !nt.apply(func(cur string) (string, mapper) {
			locs := anchoredFind(cur, rePlusConcatEP, litStartsBeforePlus(cur), 1600, nil)
			return replaceLocs(cur, locs, func(loc []int) (string, bool) {
				q1, lit, q2 := cur[loc[2]:loc[3]], cur[loc[4]:loc[5]], cur[loc[6]:loc[7]]
				if q1 != q2 {
					return "", false
				}
				expr := cur[loc[8]:loc[9]]
				tail := ""
				if loc[10] >= 0 {
					if cur[loc[10]:loc[11]] != cur[loc[14]:loc[15]] {
						return "", false
					}
					tail = cur[loc[12]:loc[13]]
				}
				// hanya bila ekspresi berada di posisi segmen path / nilai query,
				// dan literal membawa nama (bukan "/" + x saja)
				if !(strings.HasSuffix(lit, "/") || strings.HasSuffix(lit, "=") ||
					(tail != "" && strings.IndexByte("/?&.#", tail[0]) >= 0)) {
					return "", false
				}
				if len(lit) < 2 || !hasLetter(strings.TrimPrefix(strings.TrimPrefix(lit, "https://"), "http://")+tail) {
					return "", false
				}
				return q1 + lit + "{" + lastIdent(expr) + "}" + tail + q1, true
			})
		}) {
			break
		}
	}
	return nt.result(s)
}

// splitTopArgs: argumen top-level dari s[open+1:] sampai ')' penutup.
// Return (args, idxSetelahPenutup, ok).
func splitTopArgs(s string, open int) ([]string, int, bool) {
	depth := 0
	start := open + 1
	var args []string
	for i := open + 1; i < len(s) && i < open+2000; i++ {
		c := s[i]
		switch c {
		case '"', '\'', '`':
			j := skipString(s, i)
			if j < 0 {
				return nil, 0, false
			}
			i = j
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				if c != ')' {
					return nil, 0, false
				}
				args = append(args, strings.TrimSpace(s[start:i]))
				return args, i + 1, true
			}
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return nil, 0, false
}

// skipString: s[i] adalah quote pembuka; return indeks quote penutup (-1 gagal).
func skipString(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s) && j < i+4000; j++ {
		switch s[j] {
		case '\\':
			j++
		case '\n':
			if q != '`' {
				return -1
			}
		case q:
			return j
		}
	}
	return -1
}

func unquoteLit(a string) (string, bool) {
	if len(a) >= 2 && (a[0] == '"' || a[0] == '\'') && a[len(a)-1] == a[0] && !strings.ContainsAny(a[1:len(a)-1], "\"'\\") {
		return a[1 : len(a)-1], true
	}
	return "", false
}

// dotConcatEP: "".concat(e,"/api/users/").concat(t) -> "/api/users/{t}".
func dotConcatEP(s string) (string, mapper) {
	if !strings.Contains(s, ".concat(") {
		return s, nil
	}
	// kandidat: literal tepat sebelum tiap ".concat("
	var starts []int
	for i := 0; ; {
		k := strings.Index(s[i:], ".concat(")
		if k < 0 {
			break
		}
		p := i + k
		i = p + 1
		j := p - 1
		if j < 1 || (s[j] != '"' && s[j] != '\'') {
			continue
		}
		for a := j - 1; a >= 0 && a >= j-2000; a-- {
			if s[a] == '\n' || s[a] == '\\' {
				break
			}
			if s[a] == s[j] {
				starts = append(starts, a)
				break
			}
		}
	}
	locs := anchoredFind(s, reDotConcatEP, starts, 2100, nil)
	if len(locs) == 0 {
		return s, nil
	}
	var t tbuild
	prev := 0
	changed := false
	for _, loc := range locs {
		if loc[0] < prev {
			continue
		}
		head := s[loc[0] : loc[1]-len(".concat(")]
		first, _ := unquoteLit(head)
		var b strings.Builder
		b.WriteString(first)
		hasPathLit := strings.Contains(first, "/")
		end := loc[1] - 1 // posisi '(' pertama
		ok := true
		for {
			args, after, good := splitTopArgs(s, end)
			if !good {
				ok = false
				break
			}
			for _, a := range args {
				if a == "" {
					continue
				}
				if lit, isLit := unquoteLit(a); isLit {
					b.WriteString(lit)
					if strings.Contains(lit, "/") {
						hasPathLit = true
					}
				} else {
					b.WriteString("{" + lastIdent(a) + "}")
				}
			}
			end = after
			if strings.HasPrefix(s[end:], ".concat(") {
				end += len(".concat")
				continue
			}
			break
		}
		if !ok || !hasPathLit {
			continue
		}
		joined := dropLeadingPlaceholder(b.String())
		if !pathy(joined) || !hasLetter(joined) {
			continue
		}
		t.keep(s, prev, loc[0])
		t.put(loc[0], `"`+joined+`"`)
		prev = end
		changed = true
	}
	if !changed {
		return s, nil
	}
	t.keep(s, prev, len(s))
	return t.b.String(), asMapper(t.m)
}

// templateExprEP: `${a.id}` -> `{id}`; `${BASE}/api/x` di awal template -> `/api/x`.
func templateExprEP(s string) (string, mapper) {
	if !strings.Contains(s, "${") {
		return s, nil
	}
	return replaceTracked(s, reTplExprEP, func(loc []int) (string, bool) {
		if loc[0] > 0 && s[loc[0]-1] == '`' && loc[1] < len(s) && s[loc[1]] == '/' {
			return "", true
		}
		return "{" + lastIdent(s[loc[2]:loc[3]]) + "}", true
	})
}

// normaliseContentEP: pipeline pra-ekstraksi. HTML -> decode entity dulu;
// JSON -> `\/` selalu di-decode; JS/HTML -> `\/` hanya di string literal URL.
func normaliseContentEP(content string, ck contentKind) normText {
	nt := normText{s: content}
	if ck == ckHTML {
		nt.apply(decodeHTMLEntitiesEP)
	}
	decode := decodeEscapesJS
	if ck == ckJSON {
		decode = decodeEscapesEP
	}
	for i := 0; i < 3; i++ {
		changed := nt.apply(decode)
		changed = nt.apply(joinConcatEP) || changed
		changed = nt.apply(evalArrJoinEP) || changed
		changed = nt.apply(propagateEP) || changed
		if !changed {
			break
		}
	}
	// rekonstruksi route dinamis SETELAH propagasi (yang butuh ${NAME} utuh)
	nt.apply(dotConcatEP)
	nt.apply(plusConcatEP)
	nt.apply(templateExprEP)
	nt.apply(joinConcatEP)
	return nt
}
