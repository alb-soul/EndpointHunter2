# endpoint-hunter2

<img src="https://img.shields.io/badge/go-1.21-blue" alt="go 1.21"/>

**JS Endpoint Discovery Tool for Bug Bounty** — extracts hidden API endpoints from JavaScript files that are usually missed by standard recon tools. Designed as the natural follow-up to [Secrethunter2](https://github.com/alb-soul/Secrethunter2) in a recon pipeline, and also usable standalone.

## Key Features

- **Endpoint extraction from JS** — detects `fetch`, `axios.*`, `$.ajax`, `$.get/post`, `XMLHttpRequest.open`, superagent, router/app definitions, URL-variable assignments, API-path literals, and absolute URLs.
- **Body-reuse mode (`--httpx-json`)** — reads `{url, body}` directly from `httpx -json -irr`, extracting endpoints from already-fetched bodies **without re-fetching**. Streaming, so it can handle huge JSONL files.
- **Fetch mode** — feed it a URL list (`-l`, args, or stdin) and it fetches each page/JS with full retry/redirect handling.
- **FlareSolverr integration** — Cloudflare-protected targets are solved automatically. Cookie sessions are cached per-domain and **re-solved on 403/429** (expired cookies).
- **Auto base-URL detection** — picks up `axios.defaults.baseURL`, `baseUrl`, `VUE_APP_*`, `process.env.* || "..."` etc., so relative paths resolve accurately.
- **Interest scoring** — each endpoint is ranked `HIGH` / `MED` / `LOW` by path keywords.
- **Scope & noise control** — default luas (semua URL absolut terlist, termasuk sibling subdomain); `--scope` / `--scope-exact` / `-bs` untuk menyempit, static-asset filtering, dan known-endpoints filter (`-k`).
- **Param extraction** — query params, path params (`{id}`, `/:id`), template vars, and body params (kinda guessable from `body:`/`data:`/`params:` objects) are captured.
- **Multi-format output** — colored table, plain URLs, JSON, ready-to-run `curl` commands with FUZZ-injected params and body, plus a one-command **multi-stream** `--out-prefix` (`<p>.txt` / `<p>.jsonl` / `<p>.curl.sh`).
- **Fuzz mode** — `{param}` placeholders are rewritten to `FUZZ` for direct use with ffuf/nuclei.
- **Performance** — whole-content scan (not per-line), hoisted regexes, char-window context extraction, shared keep-alive HTTP transport, concurrent workers.

## Install / Build

```bash
# in project dir (main.go + extractor.go + enrich.go + go.mod)
go build -o endpoint-hunter2 .
go vet ./...
```

Requirements: Go 1.21+.

## Usage

```text
endpoint-hunter2 [flags] [url...]
```

### Extract from local JS file

```bash
endpoint-hunter2 -js app.js
endpoint-hunter2 -js bundle.js --scope example.com -o endpoints.txt
```

### Fetch mode (URL list)

```bash
cat urls.txt | endpoint-hunter2 --rate 5 --flaresolverr http://127.0.0.1:8191
endpoint-hunter2 -l urls.txt -t 20 -timeout 10
```

### httpx body-reuse mode (recommended for pipelines)

```bash
httpx -l urls.txt -json -irr -silent | endpoint-hunter2 --httpx-json - -k all-urls.txt --scope example.com
```
or from a file:

```bash
httpx -l urls.txt -json -irr -o httpx.jsonl ... 
endpoint-hunter2 --httpx-json httpx.jsonl --scope example.com
```

> `-irr` / `--include-response` makes httpx include the response **body** in its JSON output. The `--httpx-json -` reads JSONL from stdin.

### Pipeline after secrethunter2

```bash
# 1) collect secrets  2) extract endpoints without re-fetching
httpx -l all-urls.txt -json -irr -silent -o httpx.jsonl
secrethunter2 -l all-urls.txt -f http://127.0.0.1:8191 -rate 5 -o secrets
endpoint-hunter2 --httpx-json httpx.jsonl -k all-urls.txt --urls-only |
  httpx -silent | nuclei -t fuzz/
```

### Output formats

```bash
endpoint-hunter2 -js app.js                     # colored table + source refs
endpoint-hunter2 -js app.js --urls-only         # one URL per line (pipe to httpx/nuclei)
endpoint-hunter2 -js app.js --json              # full JSON array
endpoint-hunter2 -js app.js --curl              # ready-to-run curl commands
endpoint-hunter2 -js app.js --fuzz --urls-only  # {param} -> FUZZ
endpoint-hunter2 -js app.js --out-prefix out    # out.txt + out.jsonl + out.curl.sh
```

`--curl` for POST/PUT/PATCH/DELETE auto-builds a FUZZ body. `--body-format json|form|both` controls it.

## Flags

| Flag | Description |
| --- | --- |
| `-l, -list` | File with URLs to scan |
| `-k, -known` | Extra known-endpoints file to filter (host+path, case-insensitive) |
| `-js` | Local JS file to analyze |
| `--httpx-json` | JSONL from `httpx -json -irr` (body-reuse, no fetch). `-` = stdin |
| `-b, -base` | Base URL override for resolving relative paths |
| `--scope` | Only `D` + `*.D` (tanpa flag lain = semua tampil) |
| `--scope-exact D` | Tepat satu host `D` (single-flag; spasi/`=`). Bare `--scope-exact` = modifier exact untuk `--scope`/`-bs` |
| `-bs`, `--base-scope` | Scope otomatis = registrable domain host input (per source record) |
| `-t, -threads` | Concurrency (default 20) |
| `--rate` | Max requests/second (0 = unlimited) |
| `--delay` | ms delay between requests (used only when `--rate` is off) |
| `--flaresolverr` | FlareSolverr URL for Cloudflare/403 handling |
| `-H, -header` | Extra HTTP header (repeatable) |
| `--timeout` | Request timeout seconds (default 7) |
| `-ua` | Custom User-Agent |
| `--include-assets` | Include static asset URLs (JS/CSS/images) |
| `--include-external` | On by default (redundan; tetap diterima). `--include-external=false` = perilaku strict lama |
| `--urls-only` | Plain URLs, one per line |
| `--json` | JSON output |
| `--curl` | Curl command output |
| `--body-format` | `json` \| `form` \| `both` (default `json`) |
| `--fuzz` | Replace `{param}` with `FUZZ` |
| `--out-prefix` | Write `<p>.txt` + `<p>.jsonl` + `<p>.curl.sh` in one run |
| `-o, -output` | Write chosen output to a file |
| `-silent` | No banner/progress |
| `-v, -verbose` | Verbose logs (fetch + base URL detection) |
| `--no-color`, `--no-source` | Tweak display |

## How It Works

1. **Input** — URL list, local JS file, stdin, or httpx-json JSONL (fed to a worker pool).
2. **Fetch** *(fetch mode only)* — shared keep-alive transport, redirect cap, FlareSolverr cookie session cache with re-solve on 403/429, response body capped at 10 MB.
3. **Extract** — a fixed set of hoisted regexes scans the whole content once per pattern; matches are de-duplicated, resolved against auto-detected base URL, and filtered (static assets / external hosts / scope / known endpoints).
4. **Enrich** — params are pulled from a 500-char window around each match; `{param}`, `/:id` become FUZZ targets; body params attached for non-GET.
5. **Output** — ranked by interest, deduped globally, emitted in the requested format.

## Notes

- Proxy via `HTTP_PROXY`/`HTTPS_PROXY` env is honored (`ProxyFromEnvironment`).
- Start-of-line comments (`#`) in list files are skipped.
- Not a crawler — feed it pages and JS files; for crawling pair it with a spider (katana, gau, waybackurls, etc.).