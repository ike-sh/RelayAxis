"""Small real echo/peer-address fixture executed inside isolated namespaces."""

import socket
import socketserver
import sys
import threading


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while b"\n" not in data:
            part = self.request.recv(4096)
            if not part:
                return
            data += part
        self.request.sendall(self.client_address[0].encode() + b"|" + data)


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(self.client_address[0].encode() + b"|" + data, self.client_address)


def serve(host, port):
    tcp = socketserver.ThreadingTCPServer((host, port), TCP)
    tcp.daemon_threads = True
    udp = socketserver.ThreadingUDPServer((host, port), UDP)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    print("READY", flush=True)
    tcp.serve_forever()


def probe(host, port, expected_source):
    payload = b"RelayAxis real WireGuard dual-egress check\n"
    expected = expected_source.encode() + b"|" + payload
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for socktype in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(family, socktype) as sock:
            sock.settimeout(4)
            sock.connect((host, port))
            sock.sendall(payload)
            result = b""
            while len(result) < len(expected):
                part = sock.recv(65535)
                if not part:
                    break
                result += part
            if result != expected:
                raise RuntimeError(f"wrong response/source: {result!r}")
    print("TCP+UDP PASS")


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(sys.argv[2], int(sys.argv[3]))
    else:
        probe(sys.argv[2], int(sys.argv[3]), sys.argv[4])
