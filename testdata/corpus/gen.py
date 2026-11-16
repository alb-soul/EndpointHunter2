#!/usr/bin/env python3
"""Generator corpus uji endpoint-hunter2 (JSONL palsu ala `httpx -json -irr`).

    python3 testdata/corpus/gen.py                 -> testdata/corpus/corpus.jsonl
    python3 testdata/corpus/gen.py --big OUT.jsonl  -> + corpus besar (~9MB/record) utk timing
    python3 testdata/corpus/gen.py --huge OUT.jsonl -> 1 baris >64MB lalu 1 record normal
                                                       (regresi: baris raksasa tak boleh
                                                       menghentikan pembacaan record berikutnya)

Semua host fiktif (example.com / examplecdn.net / *.invalid). Ground truth:
expected.txt (wajib keluar) dan fp.txt (tidak boleh keluar), dibandingkan oleh compare.py.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

HTML_APP = r"""<!doctype html>
<html><head>
<base href="/app/">
<title>Example</title>
<script src="https://cdn.examplecdn.net/static/js/main.abc123.js"></script>
<script src="/assets/index-Ab12.js" type="module"></script>
<link rel="stylesheet" href="/assets/index-Ab12.css">
</head><body>
<div id="root" data-config="{&quot;apiUrl&quot;:&quot;https://api.example.com/v3&quot;,&quot;search&quot;:&quot;/api/search?q=x&amp;page=2&quot;}"></div>
<form action="/account/login" method="post"><input name="user"></form>
<form action="profile/update" method="POST"></form>
<a href="account/settings">Settings</a>
<a href="javascript:void(0)">x</a>
<a href="mailto:security@example.com">mail</a>
<a href="tel:+620000">tel</a>
<a href="https://twitter.com/example">tw</a>
<a href="https://www.facebook.com/example">fb</a>
<img src="/static/media/logo.5f3a.png">
<script>
  fetch("api/inline-relative");
  fetch("/api/inline-root", {method: "DELETE"});
</script>
</body></html>
"""

# Bundle minified di CDN pihak ketiga, dimuat oleh halaman app.example.com.
JS_CDN = (
    '/*! For license information please see main.abc123.js.LICENSE.txt */\n'
    '/*! @license MIT https://github.com/facebook/react/blob/main/LICENSE */\n'
    '!function(){"use strict";var e,t,n,r={};'
    'fetch("/api/users");'
    'fetch("/api/a");fetch("/api/b",{method:"POST",body:JSON.stringify({secret:1,token:2})});'
    'var o="/api/orders/".concat(e,"/items");'
    'var p="/api/v1/user/"+t+"/profile";'
    'var q=`/api/tpl/${a.id}/y`;'
    'var q2=`/api/tpl2/${ encodeURIComponent(n) }/z`;'
    'var h="\\u002fapi\\u002funicode-esc";'
    'var j="say \\u0022hi\\u0022 to /api/should-not-split";'
    'axios.post("/api/login",{username:u,password:pw});'
    'axios.get("/api/list",{params:{page:1,size:20}});'
    '$.ajax({url:"/api/legacy",type:"POST",data:{a:1,b:2}});'
    '$.getJSON("/api/jsonp-data");'
    'navigator.sendBeacon("/api/collect",x);'
    'var rq=new Request("/api/req-obj",{method:"PUT"});'
    'fetch("/api/nested",{headers:{"Content-Type":"application/json"},method:"PATCH"});'
    'this.$axios.$get("/api/nuxt-get");'
    'var routes=[{path:"/dashboard/:tab",component:D},{path:"/reports/:id/view",component:R}];'
    'var mime="application/json",mime2="text/html; charset=utf-8",dt="2024/01/02",ver="1.2.3";'
    'var i18n="errors.not_found",css="/static/css/main.8f2.css",font="/fonts/Inter.woff2",img="/images/hero.webp";'
    'var rnd="/aB3dE9fGhJ2kLmN0pQ/zX9yW8vU7tS6rR5q";'
    'var du="data:application/json;base64,eyJ9";var bl="blob:https://app.example.com/1234";'
    'var hdr=request.get("Content-Type");var envv=app.get("env");'
    'var ga="//www.google-analytics.com/analytics.js";'
    'var gql=new HttpLink({uri:"/graphql"});'
    'var geolocation="nowhere/x";'
    'var gapi="https://www.googleapis.com/youtube/v3/videos";'
    'var u2=client.get("cache-key");'
    'var tw="https://twitter.com/intent/tweet";'
    'var ws=new WebSocket("wss://rt.example.com/socket/v2");'
    'var batch="/v1/items:batchGet";'
    'var rel=fetch("./api/dot-relative"),rel2=fetch("../api/dotdot");'
    'var assets="/api/assets.list";'
    '}();\n'
    '//# sourceMappingURL=main.abc123.js.map\n'
)

# Vite bundle di origin app (same-origin) dengan axios.create baseURL ber-path.
JS_VITE = (
    'const api=axios.create({baseURL:"https://api.example.com/api/v2"});'
    'api.get("/users/me");api.post("orders",{sku:s,qty:q});'
    'const Admin=()=>import("./Admin-x1y2.js");'
    'const r=[{path:"/admin/settings",component:S}];'
    'fetch(`${BASE_URL}/api/from-unknown-base`);'
    'fetch("https://api.example.com/v2/explicit?x=1");\n'
)

# Bundle lain berisi SDK pihak ketiga dgn baseURL eksternal: TIDAK boleh membajak
# base untuk path relatif aplikasi.
JS_SDK_MIX = (
    'var mapbox=axios.create({baseURL:"https://api.mapbox-like.invalid"});'
    'fetch("/api/own-endpoint");fetch("/api/own-two",{method:"POST"});\n'
)

JSON_CONFIG = json.dumps({
    "apiUrl": "https://api.example.com/v1",
    "paths": {"login": "/auth/login", "me": "/api/v1/me"},
    "cdn": "https://cdn.examplecdn.net/static/",
}).replace("/", "\\/")  # gaya PHP json_encode: slash di-escape

NEXT_MANIFEST = (
    'self.__BUILD_MANIFEST=function(s,c){return{__rewrites:{afterFiles:[{source:"/api/proxy/:path*",'
    'destination:"https://backend.example.com/:path*"}]},"/":[s,c,"static/chunks/pages/index-1.js"],'
    '"/_app":["static/chunks/pages/_app-2.js"],"/_error":["static/chunks/pages/_error-3.js"],'
    '"/account/[id]":[s,"static/chunks/pages/account/[id]-4.js"],'
    '"/blog/[...slug]":[s,"static/chunks/pages/blog/[...slug]-5.js"],'
    'sortedPages:["/","/_app","/_error","/account/[id]","/blog/[...slug]"]}}'
    '("static/chunks/1.js","static/css/2.css"),self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();\n'
)

ANGULAR = (
    'const routes=[{path:"admin/users/:id",component:UserEditComponent},'
    '{path:"billing",loadChildren:()=>import("./billing.module").then(m=>m.BillingModule)}];'
    'class S{constructor(http){this.http=http}save(n){return this.http.post("/api/ng/save",{name:n})}'
    'load(){return this.http.get(`${this.base}/api/ng/items`)}}\n'
)

RECORDS = [
    ("https://app.example.com/", "text/html; charset=utf-8", HTML_APP),
    ("https://cdn.examplecdn.net/static/js/main.abc123.js", "application/javascript", JS_CDN),
    ("https://app.example.com/assets/index-Ab12.js", "application/javascript", JS_VITE),
    ("https://app.example.com/assets/vendor-sdk.js", "application/javascript", JS_SDK_MIX),
    ("https://app.example.com/config.json", "application/json", JSON_CONFIG),
    ("https://app.example.com/_next/static/abc/_buildManifest.js", "application/javascript", NEXT_MANIFEST),
    ("https://admin.example.com/main.js", "application/javascript", ANGULAR),
    # biner/gambar: tidak boleh diproses jadi endpoint
    ("https://app.example.com/static/media/logo.5f3a.png", "image/png", "\x89PNG /api/from-binary-image garbage"),
]


def rec(url, ctype, body):
    return {"url": url, "status_code": 200, "content_type": ctype,
            "header": {"content_type": ctype}, "body": body}


def write_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def big_body(target=9 * 1024 * 1024):
    # bundle minified "realistis": banyak deklarasi var pendek + panggilan + string acak
    chunk = []
    i = 0
    size = 0
    while size < target:
        s = ('var a%d="v%d",b%d=function(e,t){return e+t};'
             'fetch("/api/big/item%d");x.push("/static/x%d.png");'
             'var c%d={label:"Hello world %d",k:"errors.k%d"};' % (i, i, i, i % 5000, i, i, i, i))
        chunk.append(s)
        size += len(s)
        i += 1
    return "!function(){" + "".join(chunk) + "}();"


def main():
    write_jsonl(os.path.join(HERE, "corpus.jsonl"), [rec(*r) for r in RECORDS])
    args = sys.argv[1:]
    if "--big" in args:
        out = args[args.index("--big") + 1]
        body = big_body()
        recs = [rec("https://app.example.com/assets/big-%d.js" % k, "application/javascript", body) for k in range(4)]
        write_jsonl(out, recs + [rec(*r) for r in RECORDS])
    if "--huge" in args:
        out = args[args.index("--huge") + 1]
        # <-> di-escape </> oleh encoder Go (httpx) -> baris membengkak 6x
        huge = "<>" * (6 * 1024 * 1024)
        with open(out, "w", encoding="utf-8") as f:
            line = json.dumps(rec("https://app.example.com/huge.html", "text/html", huge))
            f.write(line.replace("<", "\\u003c").replace(">", "\\u003e") + "\n")
            f.write(json.dumps(rec("https://app.example.com/after-huge.js", "application/javascript",
                                   'fetch("/api/after-huge-record");')) + "\n")


if __name__ == "__main__":
    main()
