#!/usr/bin/env python3
"""Vortex Hack: bounded, authorized website configuration checks."""
import argparse
from collections import Counter
import datetime
import email.message
import json
import math
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from vortex_report import render_html

VERSION = '0.2.0'
MAX_TARGETS = 20
LIMITATIONS = ('Configuration observations require manual verification. One HEAD response per URL; '
               'no body, login, exploitation, crawling or redirect following. Missing headers alone '
               'do not establish an exploitable vulnerability. HEAD may differ from normal page responses.')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_url(value):
    if not isinstance(value, str) or not value or re.search(r'[\s\\\x00-\x1f\x7f]', value):
        raise ValueError('URLs must be nonempty strings without whitespace, controls or backslashes.')
    p = urllib.parse.urlsplit(value)
    if p.scheme not in ('http', 'https') or not p.hostname or '@' in p.netloc:
        raise ValueError('Use an http(s) URL without embedded credentials.')
    if p.query or p.fragment or '?' in value or '#' in value:
        raise ValueError('Remove query strings and fragments to avoid recording secrets.')
    if p.port == 0:
        raise ValueError('Port zero is invalid.')
    return value


def load_scope(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('Scope must be a JSON object.')
    urls = data.get('approved_urls')
    if not isinstance(urls, list) or not urls or len(urls) > MAX_TARGETS:
        raise ValueError(f'approved_urls must contain 1–{MAX_TARGETS} exact URL strings.')
    for url in urls:
        validate_url(url)
    if len(set(urls)) != len(urls):
        raise ValueError('Scope contains duplicate URLs.')
    return urls


def analyze(url, status, headers):
    findings = []

    def add(key, severity, evidence, fix):
        findings.append(dict(check=key, severity=severity, confidence='observed',
                             evidence=evidence, recommendation=fix))

    if urllib.parse.urlsplit(url).scheme == 'http':
        add('unencrypted_transport', 'medium', 'Requested URL uses HTTP.',
            'Serve this resource over HTTPS; verify HTTP redirects to HTTPS.')
    if status in (301, 302, 303, 307, 308):
        add('redirect_not_followed', 'info', 'Response redirects; destination was not requested.',
            'Approve the destination separately before scanning it.')
        return findings
    if not 200 <= status < 300:
        add('response_not_assessed', 'info', f'HTTP {status}: browser policies were not assessed.',
            'Check the intended successful response separately; HEAD may be unsupported.')
        return findings

    content_type = headers.get('Content-Type', '').split(';')[0].strip().lower()
    html = content_type in ('text/html', 'application/xhtml+xml')
    if not content_type:
        add('content_type_absent', 'review', 'Content-Type was absent; HTML-specific checks skipped.',
            'Declare the correct media type and review a normal page response.')
    if not headers.get('X-Content-Type-Options'):
        add('missing_x-content-type-options', 'low', 'X-Content-Type-Options was absent.',
            'Set X-Content-Type-Options: nosniff.')
    elif headers.get('X-Content-Type-Options').strip().lower() != 'nosniff':
        add('invalid_nosniff', 'low', 'X-Content-Type-Options did not equal nosniff.',
            'Set X-Content-Type-Options: nosniff.')
    if html:
        for key, severity, fix in [
            ('Content-Security-Policy', 'medium', 'Define and test a Content Security Policy suited to the application.'),
            ('Referrer-Policy', 'low', 'Set an appropriate Referrer-Policy, such as strict-origin-when-cross-origin.'),
        ]:
            if not headers.get(key):
                add('missing_' + key.lower(), severity, key + ' was absent on this HTML response.', fix)
        csp = headers.get('Content-Security-Policy', '')
        directives = {part.strip().split()[0].lower() for part in csp.split(';') if part.strip()}
        if not headers.get('X-Frame-Options') and 'frame-ancestors' not in directives:
            add('framing_policy_absent', 'low', 'No X-Frame-Options or CSP frame-ancestors directive observed.',
                'Restrict framing if this page should not be embedded.')
        xfo = headers.get('X-Frame-Options', '').strip().lower()
        if xfo and xfo not in ('deny', 'sameorigin') and 'frame-ancestors' not in directives:
            add('framing_policy_invalid', 'review', 'X-Frame-Options used an unrecognized value.',
                'Use DENY or SAMEORIGIN, or define CSP frame-ancestors.')
    if urllib.parse.urlsplit(url).scheme == 'https':
        hsts = headers.get('Strict-Transport-Security', '')
        if not hsts:
            add('missing_strict-transport-security', 'low', 'Strict-Transport-Security was absent.',
                'Enable HSTS after confirming HTTPS works across the intended scope.')
        else:
            match = re.search(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)', hsts, re.I)
            if not match or not match.group(1).strip('0'):
                add('hsts_not_enforced', 'review', 'HSTS had no valid positive max-age.',
                    'Review the policy and use a positive max-age when HTTPS is ready.')
    for raw in headers.get_all('Set-Cookie', []):
        # Values and cookie names are never retained in findings.
        attrs = {part.strip().split('=', 1)[0].lower() for part in raw.split(';')[1:]}
        missing = sorted({'secure', 'httponly', 'samesite'} - attrs)
        if missing:
            add('cookie_attributes', 'review', 'A response cookie lacks: ' + ', '.join(missing),
                'Review the cookie purpose; apply these attributes where appropriate.')
    return findings


def scan(url, timeout=10):
    validate_url(url)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, method='HEAD', headers={
        'User-Agent': 'Vortex-Hack/' + VERSION + ' (authorized configuration audit)'})
    started = time.monotonic()
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status, headers = response.code, response.headers
    return {'target': url, 'status': status, 'outcome': 'completed',
            'duration_ms': round((time.monotonic() - started) * 1000),
            'findings': analyze(url, status, headers)}


def error_result(url, error):
    # Do not serialize raw server text, exception messages, credentials or headers.
    cause = getattr(error, 'reason', error)
    if isinstance(cause, ssl.SSLCertVerificationError):
        message = 'TLS certificate verification failed.'
    elif isinstance(cause, TimeoutError):
        message = 'Connection timed out.'
    else:
        message = 'Connection failed. Check DNS, connectivity and target availability.'
    return {'target': url, 'status': None, 'outcome': 'error', 'error': message, 'findings': []}


def run_scan(targets, timeout=10, delay=1.0):
    results = []
    for index, url in enumerate(targets):
        if index:
            time.sleep(delay)
        try:
            results.append(scan(url, timeout))
        except (OSError, urllib.error.URLError, ValueError) as error:
            # Keep later approved targets available even when one target fails.
            results.append(error_result(url, error))
    return build_report(results)


def build_report(results, demo=False):
    counts = Counter(f['severity'] for result in results for f in result['findings'])
    return {'schema_version': 2, 'tool': 'Vortex Hack', 'version': VERSION,
            'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'demo': demo, 'limitations': LIMITATIONS,
            'summary': {'targets': len(results), 'completed': sum(r['outcome'] == 'completed' for r in results),
                        'errors': sum(r['outcome'] == 'error' for r in results),
                        'findings': sum(counts.values()), 'by_severity': dict(counts)}, 'results': results}


def demo_report():
    headers = email.message.Message()
    headers['Content-Type'] = 'text/html'
    return build_report([
        {'target': 'https://practice.example/', 'status': 200, 'outcome': 'completed', 'duration_ms': 42,
         'findings': analyze('https://practice.example/', 200, headers)},
        {'target': 'https://api.practice.example/', 'status': 200, 'outcome': 'completed',
         'duration_ms': 31, 'findings': []},
        {'target': 'https://offline.practice.example/', 'status': None, 'outcome': 'error',
         'error': 'Demonstration connection failure.', 'findings': []}], demo=True)


def positive_timeout(value):
    number = float(value)
    if not math.isfinite(number) or not 1 <= number <= 30:
        raise argparse.ArgumentTypeError('Timeout must be between 1 and 30 seconds.')
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=VERSION)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--target', action='append', help='Exact approved URL; repeat for multiple URLs')
    mode.add_argument('--all-approved', action='store_true', help='Check every URL in the scope file')
    mode.add_argument('--demo', action='store_true', help='Generate a labeled sample report without network requests')
    parser.add_argument('--scope', type=Path, help='JSON file containing approved_urls')
    parser.add_argument('--authorized', action='store_true', help='Confirm permission to check the selected URLs')
    parser.add_argument('--timeout', type=positive_timeout, default=10, help='Socket timeout, 1–30 seconds; default 10')
    parser.add_argument('--output', type=Path, default=Path('vortex-report.json'))
    parser.add_argument('--html', type=Path, help='Also write a standalone HTML report')
    parser.add_argument('--fail-on', choices=['medium', 'low', 'review'], help='Exit 2 when findings reach this threshold')
    args = parser.parse_args(argv)
    try:
        if args.html and args.html.resolve() == args.output.resolve():
            raise ValueError('JSON and HTML output paths must differ.')
        for output in [args.output, args.html]:
            if output and output.exists():
                raise ValueError('Output already exists; choose a new filename: ' + str(output))
        if args.demo:
            report = demo_report()
        else:
            if not args.authorized or not args.scope:
                raise ValueError('Provide --scope and --authorized before scanning.')
            approved = load_scope(args.scope)
            targets = approved if args.all_approved else list(dict.fromkeys(args.target))
            for target in targets:
                validate_url(target)
                if target not in approved:
                    raise ValueError('Every target must exactly match an approved_urls entry.')
            report = run_scan(targets, args.timeout)
        with args.output.open('x', encoding='utf-8') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        if args.html:
            with args.html.open('x', encoding='utf-8') as output:
                output.write(render_html(report))
    except (ValueError, TypeError, OSError) as error:
        parser.exit(1, 'Vortex: ' + str(error) + '\n')
    summary = report['summary']
    print(f"Vortex Hack {VERSION} | {summary['completed']}/{summary['targets']} completed | "
          f"{summary['findings']} findings | {summary['errors']} connection errors")
    print('JSON: ' + str(args.output))
    if args.html:
        print('HTML: ' + str(args.html))
    if args.demo:
        return 0
    if summary['errors']:
        return 1
    if args.fail_on:
        levels = {'medium': 3, 'low': 2, 'review': 1, 'info': 0}
        if any(levels[f['severity']] >= levels[args.fail_on] for r in report['results'] for f in r['findings']):
            return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
