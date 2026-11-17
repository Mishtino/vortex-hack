#!/usr/bin/env python3
"""Vortex Hack: bounded, authorized website configuration checks."""
import argparse
import datetime
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = '0.1.0'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def validate_url(value):
    p = urllib.parse.urlsplit(value)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('Use an http(s) URL without embedded credentials.')
    if p.query or p.fragment:
        raise ValueError('Remove query strings and fragments to avoid recording secrets.')
    _ = p.port  # Validate malformed ports.
    return value

def analyze(url, status, headers):
    findings = []
    def add(key, severity, evidence, fix):
        findings.append(dict(check=key, severity=severity, evidence=evidence, recommendation=fix))
    if urllib.parse.urlsplit(url).scheme == 'http':
        add('unencrypted_transport', 'medium', 'Requested URL uses HTTP.', 'Serve this resource over HTTPS; verify HTTP redirects to HTTPS.')
    if status in (301,302,303,307,308):
        add('redirect_not_followed', 'info', 'Response redirects; destination was not requested.', 'Approve the destination separately before scanning it.')
        return findings
    checks = [
        ('Content-Security-Policy', 'medium', 'Define and test a Content Security Policy suited to the application.'),
        ('X-Content-Type-Options', 'low', 'Set X-Content-Type-Options: nosniff.'),
        ('Referrer-Policy', 'low', 'Set an appropriate Referrer-Policy, such as strict-origin-when-cross-origin.'),
    ]
    if url.startswith('https://'):
        checks.append(('Strict-Transport-Security', 'low', 'Enable HSTS after confirming HTTPS works across the intended scope.'))
    for key, severity, fix in checks:
        if not headers.get(key):
            add('missing_' + key.lower(), severity, key + ' was absent on this response.', fix)
    csp = headers.get('Content-Security-Policy', '').lower()
    if not headers.get('X-Frame-Options') and 'frame-ancestors' not in csp:
        add('framing_policy_absent', 'low', 'No X-Frame-Options or CSP frame-ancestors directive observed.', 'Restrict framing if the page should not be embedded.')
    for raw in headers.get_all('Set-Cookie', []):
        # Never include cookie values in a report.
        attrs = {part.strip().split('=', 1)[0].lower() for part in raw.split(';')[1:]}
        missing = sorted({'secure', 'httponly', 'samesite'} - attrs)
        if missing:
            add('cookie_attributes', 'review', 'A response cookie lacks: ' + ', '.join(missing), 'Review the cookie purpose; apply these attributes where appropriate.')
    return findings

def scan(url, timeout=10):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'Vortex-Hack/' + VERSION + ' (authorized configuration audit)'})
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as e:
        response = e
    with response:
        status, headers = response.code, response.headers
    return {'target': url, 'status': status, 'findings': analyze(url, status, headers)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--target', required=True, help='Exact URL to check; redirects are not followed')
    parser.add_argument('--scope', required=True, type=Path, help='JSON file containing an approved_urls list')
    parser.add_argument('--authorized', action='store_true', help='Confirm permission to check this URL')
    parser.add_argument('--output', type=Path, default=Path('vortex-report.json'))
    args = parser.parse_args()
    if not args.authorized:
        parser.error('Confirm target authorization with --authorized.')
    try:
        target = validate_url(args.target)
        scope = json.loads(args.scope.read_text())
        if target not in scope['approved_urls']:
            raise ValueError('Target must exactly match an approved_urls entry in the scope file.')
        report = {'tool': 'Vortex Hack', 'version': VERSION, 'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'limitations': 'One HEAD response only. Findings require manual verification; this is not a comprehensive vulnerability assessment.'}
        report.update(scan(target))
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, urllib.error.URLError) as e:
        parser.exit(1, 'Scan failed: ' + str(e) + '\n')
    print('Vortex Hack | HTTP ' + str(report['status']))
    for finding in report['findings']:
        print('[' + finding['severity'].upper() + '] ' + finding['check'])
    print('Report: ' + str(args.output))

if __name__ == '__main__':
    main()
