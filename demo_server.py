"""Local-only sample site with deliberately incomplete security headers."""
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'<h1>Local Demo Website</h1><p>Educational scanner target</p>')

if __name__ == '__main__':
    print('Local demo: http://127.0.0.1:8765')
    HTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
