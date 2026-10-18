"""Loopback HTTP plumbing shared by the two-party network and owner apps.

Same rules as demo_server.py: exact Host/Origin, a per-process token for every
POST, JSON bodies only, no filesystem browsing and no-store responses.

Public-host mode (a hosted demo behind an HTTPS reverse proxy) is on when all
three LATCH_*_ORIGIN variables are set. Each server then also accepts its own
public origin, and only the site may frame the owner apps.
"""
import json
import os
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / 'web'
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-src {frames}; frame-ancestors {ancestors}; base-uri 'none'; form-action 'none'")
STATIC = {'/style.css': ('style.css', 'text/css; charset=utf-8'),
          '/favicon.svg': ('favicon.svg', 'image/svg+xml'),
          '/party.js': ('party.js', 'application/javascript'),
          '/network.js': ('network.js', 'application/javascript'),
          '/stage.js': ('stage.js', 'application/javascript'),
          '/landing.js': ('landing.js', 'application/javascript')}


def public_origins():
    """{'site', 'alice', 'bob'} -> 'https://host', or None for loopback-only."""
    names = {'site': 'LATCH_SITE_ORIGIN', 'alice': 'LATCH_ALICE_ORIGIN', 'bob': 'LATCH_BOB_ORIGIN'}
    values = {k: os.environ.get(v, '') for k, v in names.items()}
    if not any(values.values()):
        return None
    for key, value in values.items():
        if not re.fullmatch(r'https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?', value):
            raise RuntimeError(f'{names[key]} must be https://<lowercase host>, with no port or path')
    if len(set(values.values())) != 3:
        raise RuntimeError('the site and each owner app need distinct origins')
    return values


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as handle:
        json.dump(value, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def call(url, path, body=None, token=None, timeout=20):
    """Client side of another loopback service (the network or relay)."""
    data = None if body is None else json.dumps(body).encode()
    headers = {'Host': url.split('//', 1)[1]}
    if body is not None:
        headers.update({'Content-Type': 'application/json', 'X-Latch-Token': token or ''})
    request = urllib.request.Request(url + path, data=data, headers=headers, method='GET' if body is None else 'POST')
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


class Handler(BaseHTTPRequestHandler):
    server_version = 'LatchLocal/0.2'
    page = 'party.html'
    pages = {}
    # Owner apps may be framed only by the local network's stage page; the
    # network page itself frames the two apps and is never framed.
    frame_ancestors = "'none'"
    frame_sources = "'none'"
    public_origin = None  # This server's https:// origin in public-host mode.

    def log_message(self, fmt, *args):
        pass

    def send(self, code, data, kind='application/json'):
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        self.send_response(code)
        for name, value in (('Content-Type', kind), ('Content-Length', str(len(data))),
                ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'),
                ('Referrer-Policy', 'no-referrer'),
                ('Content-Security-Policy', CSP.format(frames=self.frame_sources, ancestors=self.frame_ancestors))):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def domain_ok(self):
        port = self.server.server_address[1]
        allowed = {f'127.0.0.1:{port}', f'localhost:{port}'}
        origins = {f'http://{h}' for h in allowed}
        if self.public_origin:
            allowed.add(self.public_origin.removeprefix('https://'))
            origins.add(self.public_origin)
        origin = self.headers.get('Origin')
        return self.headers.get('Host', '') in allowed and (origin is None or origin in origins)

    def do_GET(self):
        if not self.domain_ok():
            return self.send(403, {'error': 'Local origin required.'})
        path = self.path.split('?', 1)[0]
        if path == '/' or path in self.pages:
            page = self.page if path == '/' else self.pages[path]
            return self.send(200, (WEB / page).read_bytes(), 'text/html; charset=utf-8')
        if path in STATIC:
            name, kind = STATIC[path]
            return self.send(200, (WEB / name).read_bytes(), kind)
        result = self.server.app.get(path, self.path)
        return self.send(404, {'error': 'Not found.'}) if result is None else self.send(200, result)

    def do_POST(self):
        if not self.domain_ok() or self.headers.get('X-Latch-Token', '') not in self.server.app.tokens():
            return self.send(403, {'error': 'Local session required.'})
        if self.headers.get('Content-Type') != 'application/json':
            return self.send(415, {'error': 'JSON required.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 200_000:
                raise ValueError('Invalid request size.')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError('JSON object required.')
            return self.send(200, self.server.app.post(self.path, body, self.headers.get('X-Latch-Token')))
        except (ValueError, TypeError, KeyError) as exc:
            return self.send(409, {'error': str(exc)})
        except (RuntimeError, OSError):
            return self.send(409, {'error': 'Operation refused. Private state retained; nothing new was authorized.'})
