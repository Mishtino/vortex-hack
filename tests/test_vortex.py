import contextlib
import email.message
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

from vortex import analyze, build_report, load_scope, main, run_scan, scan, validate_url
from vortex_report import render_html


def headers(**values):
    result = email.message.Message()
    for key, value in values.items():
        result[key.replace('_', '-')] = value
    return result


class Handler(BaseHTTPRequestHandler):
    visits = []

    def do_HEAD(self):
        self.visits.append(self.path)
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/never-follow')
        elif self.path == '/unsupported':
            self.send_response(405)
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Set-Cookie', 'session=TOPSECRET; Path=/')
        self.end_headers()

    def log_message(self, *args):
        pass


class Tests(unittest.TestCase):
    def test_reject_unsafe_urls(self):
        for value in ['file:///etc/passwd', 'https://user:pass@example.com/',
                      'https://example.com/?secret=1', 'https://example.com/#section',
                      'https://example.com/\n', 'https://example.com\\evil',
                      'https://example.com:0/', 'https://example.com:90000/', 7, None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_url(value)

    def test_cookie_values_redacted(self):
        h = headers(Content_Type='text/html')
        h.add_header('Set-Cookie', 'session=TOPSECRET; Path=/')
        findings = analyze('https://example.com/', 200, h)
        self.assertNotIn('TOPSECRET', str(findings))
        self.assertNotIn('session', str(findings))
        self.assertIn('cookie_attributes', str(findings))

    def test_api_does_not_get_html_specific_findings(self):
        result = analyze('https://example.com/', 200, headers(Content_Type='application/json'))
        keys = [f['check'] for f in result]
        self.assertNotIn('missing_content-security-policy', keys)
        self.assertNotIn('framing_policy_absent', keys)
        self.assertIn('missing_strict-transport-security', keys)

    def test_error_response_is_not_assessed_as_page(self):
        result = analyze('https://example.com/', 405, headers(Content_Type='text/html'))
        self.assertEqual([f['check'] for f in result], ['response_not_assessed'])

    def test_declared_policies_remove_corresponding_findings(self):
        h = headers(Content_Type='text/html', Content_Security_Policy="default-src 'self'; frame-ancestors 'none'",
                    Referrer_Policy='no-referrer', X_Content_Type_Options='nosniff',
                    Strict_Transport_Security='max-age=31536000')
        h.add_header('Set-Cookie', 'session=secret; Secure; HttpOnly; SameSite=Lax')
        self.assertEqual(analyze('https://example.com/', 200, h), [])

    def test_invalid_policies_flagged(self):
        h = headers(Content_Type='text/html', X_Content_Type_Options='wrong',
                    Strict_Transport_Security='max-age=0', X_Frame_Options='ALLOWALL')
        keys = [f['check'] for f in analyze('https://example.com/', 200, h)]
        self.assertIn('invalid_nosniff', keys)
        self.assertIn('hsts_not_enforced', keys)
        self.assertIn('framing_policy_invalid', keys)

    def test_html_escapes_untrusted_target_and_evidence(self):
        result = {'target': 'https://example.com/<script>alert(1)</script>', 'status': 200,
                  'outcome': 'completed', 'findings': [{'check': '<img src=x onerror=alert(1)>',
                  'severity': 'review', 'evidence': '<script>bad()</script>', 'recommendation': '"<unsafe>"'}]}
        output = render_html(build_report([result]))
        self.assertNotIn('<script>', output)
        self.assertNotIn('<img', output)
        self.assertIn('&lt;script&gt;', output)
        self.assertIn("default-src 'none'", output)

    def test_batch_continues_after_connection_error_and_redacts_exception(self):
        success = {'target': 'https://second.example/', 'status': 200, 'outcome': 'completed', 'findings': []}
        with patch('vortex.scan', side_effect=[urllib.error.URLError('secret-token'), success]), patch('vortex.time.sleep') as delay:
            report = run_scan(['https://first.example/', 'https://second.example/'])
        delay.assert_called_once_with(1.0)
        self.assertEqual(report['summary']['errors'], 1)
        self.assertEqual(report['summary']['completed'], 1)
        self.assertNotIn('secret-token', json.dumps(report))

    def test_scope_schema_rejects_invalid_lists(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'scope.json'
            for data in [[], {}, {'approved_urls': 'https://example.com/'},
                         {'approved_urls': []}, {'approved_urls': [8]},
                         {'approved_urls': ['https://example.com/'] * 2},
                         {'approved_urls': [f'https://example.com/{i}' for i in range(21)]}]:
                path.write_text(json.dumps(data))
                with self.subTest(data=data), self.assertRaises(ValueError):
                    load_scope(path)

    def test_scope_is_checked_before_any_network_request(self):
        with tempfile.TemporaryDirectory() as folder, patch('vortex.scan') as network:
            root = Path(folder)
            scope = root / 'scope.json'
            scope.write_text('{"approved_urls": ["https://approved.example/"]}')
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['--target', 'https://approved.example/', '--target', 'https://outside.example/',
                      '--scope', str(scope), '--authorized', '--output', str(root / 'result.json')])
            network.assert_not_called()

    def test_authorization_is_required(self):
        with patch('vortex.scan') as network, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['--target', 'https://example.com/'])
        network.assert_not_called()

    def test_timeout_must_be_finite_and_bounded(self):
        for value in ['nan', 'inf', '0', '31']:
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['--demo', '--timeout', value])

    def test_demo_has_no_network_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as folder, patch('vortex.scan') as network:
            root = Path(folder)
            arguments = ['--demo', '--output', str(root / 'report.json'), '--html', str(root / 'report.html')]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 0)
            report = json.loads((root / 'report.json').read_text())
            self.assertTrue(report['demo'])
            self.assertIn('DEMONSTRATION DATA', (root / 'report.html').read_text())
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(arguments)
            network.assert_not_called()

    def test_real_local_cli_and_redirect_boundary(self):
        Handler.visits = []
        server = HTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            base = 'http://127.0.0.1:' + str(server.server_port)
            self.assertEqual(scan(base + '/redirect')['status'], 302)
            self.assertNotIn('/never-follow', Handler.visits)
            self.assertEqual(scan(base + '/unsupported')['findings'][-1]['check'], 'response_not_assessed')
            with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
                root = Path(folder)
                scope = root / 'scope.json'
                scope.write_text(json.dumps({'approved_urls': [base + '/']}))
                code = main(['--all-approved', '--scope', str(scope), '--authorized',
                             '--output', str(root / 'out.json'), '--html', str(root / 'out.html'), '--fail-on', 'medium'])
                self.assertEqual(code, 2)
                output = (root / 'out.json').read_text()
                self.assertNotIn('TOPSECRET', output)
                self.assertEqual(json.loads(output)['summary']['completed'], 1)
                self.assertTrue((root / 'out.html').is_file())
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == '__main__':
    unittest.main()
