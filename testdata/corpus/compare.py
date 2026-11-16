#!/usr/bin/env python3
"""Bandingkan output endpoint-hunter2 dengan ground truth corpus.

    python3 testdata/corpus/compare.py <prefix>     # baca <prefix>.txt + <prefix>.jsonl

Cetak: TP / FN / FP / lain-lain + kecocokan method & params, exit 0 selalu.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_expected():
    out = []
    for line in open(os.path.join(HERE, "expected.txt"), encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        params = parts[2].split(",") if len(parts) > 2 else []
        out.append((parts[0], parts[1], params))
    return out


def load_fp():
    return [l.rstrip("\n") for l in open(os.path.join(HERE, "fp.txt"), encoding="utf-8")
            if l.strip() and not l.startswith("#")]


def main():
    prefix = sys.argv[1]
    urls = [l.strip() for l in open(prefix + ".txt", encoding="utf-8") if l.strip()]
    recs = {}
    if os.path.exists(prefix + ".jsonl"):
        for l in open(prefix + ".jsonl", encoding="utf-8"):
            if l.strip():
                r = json.loads(l)
                recs.setdefault(r["url"], []).append(r)
    exp = load_expected()
    fps = load_fp()
    urlset = set(urls)
    tp = [e for e in exp if e[1] in urlset]
    fn = [e for e in exp if e[1] not in urlset]
    fp_hits = sorted({u for u in urls for f in fps if f in u})
    expset = {e[1] for e in exp}
    other = sorted(u for u in urls if u not in expset and u not in fp_hits)
    bad_method, bad_params = [], []
    for m, u, ps in tp:
        rs = recs.get(u, [])
        methods = {r.get("method") for r in rs}
        if rs and m not in methods:
            bad_method.append("%s %s (dapat %s)" % (m, u, ",".join(sorted(x or "" for x in methods))))
        got = set()
        for r in rs:
            got |= set(r.get("params") or []) | set(r.get("body_params") or [])
        miss = [p for p in ps if p not in got]
        if rs and miss:
            bad_params.append("%s kurang %s (dapat %s)" % (u, miss, sorted(got)))
    print("total output   : %d URL" % len(urls))
    print("TP (expected)  : %d/%d" % (len(tp), len(exp)))
    print("FN (terlewat)  : %d" % len(fn))
    for e in fn:
        print("   - %s %s" % (e[0], e[1]))
    print("FP (terlarang) : %d" % len(fp_hits))
    for u in fp_hits:
        print("   ! %s" % u)
    print("method salah   : %d" % len(bad_method))
    for x in bad_method:
        print("   ~ %s" % x)
    print("params kurang  : %d" % len(bad_params))
    for x in bad_params:
        print("   ~ %s" % x)
    print("lain-lain      : %d" % len(other))
    for u in other:
        print("   ? %s" % u)


if __name__ == "__main__":
    main()
