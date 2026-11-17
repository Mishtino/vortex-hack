# Vortex Hack

**Vortex Technologies · version 0.3.0**

A Python toolkit for authorized website configuration reviews. Approve exact URLs, run bounded checks, and review evidence and remediation in JSON or a standalone HTML report. Python 3.10+; no runtime dependencies.

## Quick start

```bash
git clone https://github.com/Mishtino/vortex-hack.git
cd vortex-hack
python3 vortex.py --help
```

To preview the reporting interface without contacting any systems:

```bash
python3 vortex.py --demo --output demo.json --html demo.html
```

Open `demo.html` in your browser. Its data is explicitly labeled as a demonstration. A generated preview is also included at `docs/demo-report.html`.

## Local practice

Start a practice server in a separate terminal:

```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

Then run:

```bash
python3 vortex.py --target http://127.0.0.1:8000/ --scope scope.example.json --authorized --output local.json --html local.html
```

On Windows, use `python` if `python3` is unavailable.

## Approved websites and batch reviews

Create `scope.local.json` containing only URLs you have permission to test:

```json
{
  "approved_urls": [
    "https://your-site.example/",
    "https://your-site.example/account"
  ]
}
```

Use your actual approved URLs in place of these examples. URLs must match exactly, including trailing slashes. A scope file is an operator control, not proof of ownership.

```bash
python3 vortex.py --all-approved --scope scope.local.json --authorized --output review.json --html review.html
```

Or repeat `--target` to select specific URLs from that scope. Every selected URL is validated before the first request. Each scope supports up to 20 unique URLs. Requests are sequential with a one-second pause between targets. Redirects are reported and never followed. HTTPS uses certificate verification; environment proxy settings are not used.

Existing output files are protected from overwriting. Choose new filenames for each run. Keep reports private: URLs and paths may disclose information about your infrastructure. Avoid secrets in paths; query strings and embedded login credentials are rejected.

## Checks and interpretation

| Check | Applies to | Interpretation |
| --- | --- | --- |
| HTTP transport | All responses | HTTP request is unencrypted; a redirect response still needs separate HTTPS review |
| CSP, referrer and framing policies | Successful HTML responses | Missing policies are hardening observations, not proof of exploitation |
| MIME sniffing protection | Successful responses | Checks for `X-Content-Type-Options: nosniff` |
| HSTS presence and positive max-age | Successful HTTPS responses | Does not audit all policy semantics, preload status or subdomains |
| Cookie attribute presence | Successful responses | Context-dependent review; cookie names and values are not retained |
| Redirect or unsuccessful response | All URLs | Assessed separately; does not infer page policies from an error page |

No vulnerability score is assigned. Severity is a triage aid. One HEAD response cannot establish complete application security; headers can vary by route, method, authentication and proxy. This release does not crawl, read bodies, attempt logins or exploit systems. AI analysis and a hosted dashboard are not implemented yet.

HTML reports have no JavaScript, remote fonts, analytics or external assets. Report text is escaped and the HTML includes a restrictive content security policy.

## Compare reviews offline

Save one scan before a configuration change and another afterward, then compare the JSON files:

```bash
python3 vortex_compare.py --baseline before.json --current after.json --output changes.json --html changes.html
```

The comparator makes no network requests. After installation it is also available as `vortex-compare`.

| State | Meaning |
| --- | --- |
| New | A check appears in the current report |
| Persistent | The same check and observations remain |
| Changed | Severity, evidence, recommendation or duplicate count changed |
| Resolved | No longer observed under matching successful assessment coverage |
| Unverified | A target failed, was omitted, changed coverage, or lacks comparable coverage metadata |

Resolved is an observation, not proof that an exploitable vulnerability was fixed. Comparison groups findings by exact target URL and check; duplicate cookie observations retain their counts. Stable finding IDs are derived from the URL and check, not cookie identities. Severity and recommendation changes are tracked as changed, not automatically classified as regressions.

Coverage includes the check profile, method, status and response media type. Legacy v0.2 reports can be imported but cannot establish resolution without coverage metadata. Imported reports are validated, capped at 5 MiB each and treated as untrusted text; authenticity is not verified. Demo and real reports cannot be mixed.

Add `--fail-on-new` to return exit code 2 when new or changed groups exist; otherwise comparison returns 0, or 1 on invalid input or write failure. Existing output files are protected. Scan exit codes are documented below.

A reproducible synthetic comparison is included:

```bash
python3 vortex_compare.py --baseline docs/demo-baseline.json --current docs/demo-current.json --output example-changes.json --html example-changes.html
```

Open `docs/demo-comparison.html` for the generated preview. All sample reports are labeled as demonstrations.

## Automation and installation

Optional local installation provides the `vortex-hack` command:

```bash
python3 -m pip install .
vortex-hack --help
```

The direct `python3 vortex.py` command needs no installation. Package installation requires setuptools as a build dependency.

Use `--timeout 10` to set the socket timeout (1–30 seconds). This is not a strict total wall-clock deadline: DNS and slow responses can take longer.

`--fail-on medium` returns exit code 2 for medium observations. `low` also includes low observations; `review` includes review observations as well. Connection errors return exit code 1 and retain results from other targets. A successful run returns 0. Demo mode always returns 0 after writing its sample report. JSON schema version 2 contains stable finding IDs, per-response assessment metadata, `summary` and a `results` array; it replaces the v0.1 single-target top-level fields.

## Verification

```bash
python3 -m unittest discover -s tests -v
```

Tests use a local HTTP server and mocked failures. They verify redirect isolation, CLI reports, whole-batch scope validation, redaction, HTML escaping, policy interpretation output protection and conservative offline comparisons. GitHub Actions runs the suite and builds a package on Python 3.10, 3.12 and 3.13.

See `CHANGELOG.md` and `docs/ROADMAP.md` for release changes and planned work.
