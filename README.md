# Vortex Hack 0.1

A fresh Vortex Technologies Python command-line project for authorized website configuration reviews. Python 3.10+; standard library only, with no pip packages required.

## Run in Kali, Linux or Windows

Extract this ZIP, open a terminal inside `vortex-hack`, and run:

```bash
python3 vortex.py --help
```

For a local practice run, start a server in another terminal:

```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

Then run:

```bash
python3 vortex.py --target http://127.0.0.1:8000/ --scope scope.example.json --authorized --output vortex-report.json
```

On Windows use `python` if `python3` is unavailable. For your own website, create a scope JSON file with its exact URL in `approved_urls`, then pass that URL and file. Scope is an operator control, not proof of ownership.

## What works

- One HTTP HEAD request to the explicitly approved URL, with a 10-second socket timeout.
- Default certificate verification for HTTPS connections.
- Checks for HTTP transport, missing browser security headers, framing policy, and cookie attributes.
- No automatic redirect following; redirected URLs require separate approval.
- JSON findings with evidence and practical remediation suggestions. Cookie values and response bodies are not saved.

These are configuration observations, not confirmed exploitable vulnerabilities. Headers may vary by route, method, proxy, or response status; cookies may intentionally omit some attributes. HEAD can be unsupported; a 405 response does not establish the configuration of a normal GET page. Review findings manually. Reports contain the requested URL: use paths without secrets.

## Verify

```bash
python3 -m unittest discover -s tests -v
```

Tests cover local HTTP responses, redirect isolation, credential/query rejection, and cookie redaction. No public systems are scanned during testing.

## Next versions

AI-assisted explanations, HTML reports, additional lab checks and a dashboard are planned, not implemented. This release does not exploit systems, try passwords, enumerate targets, or claim full vulnerability coverage.
