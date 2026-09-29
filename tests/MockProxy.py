"""Loopback-only fixture: implements real SOCKS5/RFC1929 and HTTP CONNECT authentication."""
import argparse
import base64
import json
from pathlib import Path
import socket
import socketserver
import threading

EXPECTED_USER = b'fixture-user'
EXPECTED_PASS = b'fixture-password'


def read_exact(sock, count):
    data = b''
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


def read_headers(sock):
    data = b''
    while b'\r\n\r\n' not in data:
        data += read_exact(sock, 1)
        if len(data) > 32768:
            raise ValueError('request too large')
    return data


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            if self.server.kind == 'socks':
                version, count = read_exact(self.request, 2)
                methods = read_exact(self.request, count)
                if version != 5 or 2 not in methods:
                    self.request.sendall(b'\x05\xff')
                    return
                self.request.sendall(b'\x05\x02')
                version, size = read_exact(self.request, 2)
                user = read_exact(self.request, size)
                password = read_exact(self.request, read_exact(self.request, 1)[0])
                accepted = version == 1 and user == EXPECTED_USER and password == EXPECTED_PASS
                self.server.record('auth_ok' if accepted else 'auth_failed')
                self.request.sendall(b'\x01' + (b'\x00' if accepted else b'\x01'))
                if not accepted:
                    return
                version, command, _, atyp = read_exact(self.request, 4)
                if version != 5 or command != 1:
                    return
                if atyp == 1:
                    read_exact(self.request, 4)
                elif atyp == 3:
                    read_exact(self.request, read_exact(self.request, 1)[0])
                elif atyp == 4:
                    read_exact(self.request, 16)
                else:
                    return
                read_exact(self.request, 2)
                self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50')
                read_headers(self.request)
                body = b'MOCK_PROXY_OK'
            elif self.server.kind == 'http':
                headers = read_headers(self.request)
                expected = b'proxy-authorization: basic ' + base64.b64encode(EXPECTED_USER+b':'+EXPECTED_PASS)
                accepted = expected.lower() in headers.lower()
                self.server.record('auth_ok' if accepted else 'auth_failed')
                if not accepted:
                    self.request.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    return
                if headers.startswith(b'CONNECT '):
                    self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    read_headers(self.request)
                body = b'MOCK_PROXY_OK'
            else:
                read_headers(self.request)
                self.server.record('direct_origin')
                body = b'DIRECT_ORIGIN'
            self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
        except (OSError, EOFError, ValueError):
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def record(self, event):
        with self.events_lock:
            with self.events.open('a') as out:
                out.write(event+'\n')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--ready', required=True)
    p.add_argument('--events', required=True)
    args = p.parse_args()
    servers = []
    for kind in ('socks', 'http', 'origin'):
        server = Server(('127.0.0.1', 0), Handler)
        server.kind = kind
        server.events = Path(args.events)
        server.events_lock = threading.Lock()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    Path(args.ready).write_text(json.dumps({s.kind: s.server_address[1] for s in servers}))
    try:
        threading.Event().wait()
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()


if __name__ == '__main__':
    main()
