#!/usr/bin/env python3
import http.server
import os
import subprocess
import sys
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        target = '/body?' + 'q' * 4175
        if self.path.startswith('/body') and self.path != target:
            self.send_error(404)
            return
        if self.path == '/lf':
            self.connection.sendall(
                b'HTTP/1.1 200 OK\nContent-Security-Policy: ' + b'x' * 4175 +
                b'\nContent-Length: 3\n\nOK\n')
            return
        redirect = self.path == '/redirect'
        self.send_response(302 if redirect else 200)
        if not self.path.startswith('/body'):
            length = 4096 if self.path == '/boundary' else 4175
            value = 'x' * (length - len('Content-Security-Policy: \r\n'))
            if self.path == '/folded':
                value += '\r\n ' + 'y' * 4175
            self.send_header('Content-Security-Policy', value)
        if redirect:
            self.send_header('Location', target)
        body = b'' if redirect else b'OK\n'
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    binary = sys.argv[1:] or [os.path.join(os.environ['BUILD_BIN_DIR'], 'uclient-fetch')]
    try:
        for path in ('/boundary', '/long', '/folded', '/redirect', '/lf'):
            result = subprocess.run(
                binary + ['-q', '-T', '2', '-O', '-',
                 f'http://127.0.0.1:{server.server_port}{path}'],
                capture_output=True, timeout=5)
            if result.returncode != 0 or result.stdout != b'OK\n':
                raise SystemExit(f'{path}: exit {result.returncode}, '
                                 f'body {result.stdout!r}, error {result.stderr!r}')
            print(f'{path}: OK')
    finally:
        server.shutdown()
        thread.join()
