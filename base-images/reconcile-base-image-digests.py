#!/usr/bin/env python3
"""
Reconcile the published Quay digests against the Java comparison blog.

Parses the registry table out of the HTML and Markdown deliverables and checks
every declared digest prefix against the live registry. Also re-pulls each
`-base` tag and asserts it carries no application JAR, which is the property
that separates a base image from an application image.

Usage:  ./reconcile-javascript-digests.py [--html FILE] [--md FILE] [--scan]

This lives in the repo rather than /tmp because systemd-tmpfiles-clean.timer
wipes /tmp on a schedule and the previous copy was lost that way.
"""

import argparse
import json
import re
import subprocess
import sys
import urllib.request

REPO = "hellodk/base-image"
HTML = "/home/dk/Documents/blogs/2026-10-02-java-distroless-cve-hunt/2026-10-02-java-distroless-cve-hunt.html"
MD = "/home/dk/Documents/blogs/2026-10-02-java-distroless-cve-hunt/2026-10-02-java-distroless-cve-hunt-medium.md"

# digest-prefix -> tag, built from the deliverables at parse time
ROW_RE = re.compile(
    r"<tr[^>]*><td><code>([a-z0-9.\-]+)</code>.*?<code>([0-9a-f]{8})…</code></td></tr>", re.S
)
MD_ROW_RE = re.compile(r"^\|\s*`([a-z0-9.\-]+)`.*?\|\s*`([0-9a-f]{8})…`\s*\|", re.M)

BASE_TAGS = (
    "hummingbird-4.0.2-java21-base",
    "temurin-4.0.2-java21-base",
    "corretto-4.0.2-java21-base",
)


def token():
    url = (
        "https://quay.io/v2/auth?service=quay.io"
        f"&scope=repository:{REPO}:pull"
    )
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)["token"]


ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)


def manifest_digest(tok, tag):
    """Return the authoritative digest for a tag.

    Read from the Docker-Content-Digest response header rather than parsing the
    body. If the Accept header omits the single-arch manifest media types Quay
    answers with a synthesised multi-arch index, whose digest does not match the
    image that was actually pushed.
    """
    req = urllib.request.Request(
        f"https://quay.io/v2/{REPO}/manifests/{tag}",
        headers={"Authorization": f"Bearer {tok}", "Accept": ACCEPT},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.headers.get("Docker-Content-Digest", "")


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def check_no_jar(tag):
    """A base image must not contain an application JAR."""
    r = run(
        f"docker run --rm --entrypoint sh quay.io/{REPO}:{tag} "
        "-c 'ls -A /app 2>/dev/null; ls /app/*.jar 2>/dev/null'"
    )
    out = r.stdout.strip()
    return out == "", out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--html", default=HTML)
    ap.add_argument("--md", default=MD)
    ap.add_argument("--scan", action="store_true", help="also Trivy-scan the base tags")
    args = ap.parse_args()

    html = open(args.html, encoding="utf-8").read()
    md = open(args.md, encoding="utf-8").read()

    h_rows = {t: d for t, d in ROW_RE.findall(html)}
    m_rows = {t: d for t, d in MD_ROW_RE.findall(md)}

    print(f"html rows: {len(h_rows)}   md rows: {len(m_rows)}")
    only_h = set(h_rows) - set(m_rows)
    only_m = set(m_rows) - set(h_rows)
    if only_h:
        print(f"  in html only: {sorted(only_h)}")
    if only_m:
        print(f"  in md only:   {sorted(only_m)}")

    tok = token()
    fails = []

    print("\n%-34s %-10s %-10s %s" % ("TAG", "HTML", "MD", "REGISTRY"))
    print("-" * 70)
    for tag in sorted(set(h_rows) | set(m_rows)):
        hd = h_rows.get(tag, "-")
        mdv = m_rows.get(tag, "-")
        try:
            real = manifest_digest(tok, tag)
            hexd = real.split(":", 1)[-1]  # drop the "sha256:" algorithm prefix
            ok = bool(hexd) and hexd.startswith(hd if hd != "-" else mdv)
            reg = hexd[:8] + ("\u2026" if ok else "  MISMATCH")
            if not ok:
                fails.append(f"{tag}: doc says {hd}/{mdv}, registry has {hexd[:8]}")
        except Exception as e:  # noqa: BLE001
            reg = f"ERROR {e}"
            fails.append(f"{tag}: {e}")
        agree = "yes" if hd == mdv else f"NO ({hd} vs {mdv})"
        if hd != mdv:
            fails.append(f"{tag}: html/md digest disagree")
        print("%-34s %-10s %-10s %s" % (tag, hd, mdv, reg))

    print("\nbase images must contain no application JAR")
    for tag in BASE_TAGS:
        clean, out = check_no_jar(tag)
        print(f"  {tag:<34} {'clean' if clean else 'CONTAINS: ' + out}")
        if not clean:
            fails.append(f"{tag}: base image contains {out}")

    if args.scan:
        print("\ntrivy re-scan of base tags")
        for tag in BASE_TAGS:
            r = run(
                f"trivy image --quiet --scanners vuln --format json "
                f"quay.io/{REPO}:{tag}"
            )
            try:
                d = json.loads(r.stdout)
            except json.JSONDecodeError:
                fails.append(f"{tag}: trivy produced no JSON")
                continue
            n = sum(
                len(x.get("Vulnerabilities") or [])
                for x in d.get("Results") or []
            )
            print(f"  {tag:<34} {n} findings")
            if n:
                fails.append(f"{tag}: {n} findings")

    print()
    if fails:
        print(f"FAIL ({len(fails)})")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("PASS - docs, registry and JAR-free base images all agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
