package main

import (
	"fmt"
	"strings"
	"testing"
)

// bundleMinified: bundle "realistis" (banyak var pendek, fungsi, fetch, string).
func bundleMinified(target int) string {
	var b strings.Builder
	b.WriteString("!function(){")
	for i := 0; b.Len() < target; i++ {
		fmt.Fprintf(&b, `var a%d="v%d",b%d=function(e,t){return e+t};fetch("/api/big/item%d");x.push("/static/x%d.png");var c%d={label:"Hello world %d",k:"errors.k%d"};`,
			i, i, i, i%5000, i, i, i, i)
	}
	b.WriteString("}();")
	return b.String()
}

// BenchmarkExtractBigBundle: regresi performa (dulu propagasi O(decl x size)).
//
//	go test -run x -bench ExtractBig -benchtime 1x -cpuprofile cpu.out
func BenchmarkExtractBigBundle(b *testing.B) {
	js := bundleMinified(2 << 20)
	b.SetBytes(int64(len(js)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := Extract(js, ExtractOptions{PageURL: "https://app.example.com/assets/big.js"})
		if len(r.Endpoints) == 0 {
			b.Fatal("no endpoints")
		}
	}
}
