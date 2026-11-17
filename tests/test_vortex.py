import email.message
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from vortex import analyze, scan, validate_url

class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://127.0.0.1:1/never-follow')
        else:
            self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass

class Tests(unittest.TestCase):
    def test_reject_unsafe_urls(self):
        for value in ['file:///etc/passwd', 'https://user:pass@example.com/', 'https://example.com/?secret=1']:
            with self.assertRaises(ValueError):
                validate_url(value)
    def test_cookie_values_redacted(self):
        h = email.message.Message()
        h.add_header('Set-Cookie', 'session=TOPSECRET; Path=/')
        self.assertNotIn('TOPSECRET', str(analyze('https://example.com/', 200, h)))
    def test_real_local_request_and_redirect_boundary(self):
        server = HTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            base = 'http://127.0.0.1:' + str(server.server_port)
            self.assertEqual(scan(base + '/')['status'], 200)
            result = scan(base + '/redirect')
            self.assertEqual(result['status'], 302)
            self.assertIn('redirect_not_followed', str(result))
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

if __name__ == '__main__':
    unittest.main()
