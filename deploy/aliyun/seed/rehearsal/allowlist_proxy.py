#!/usr/bin/env python3
"""CONNECT-only TCP tunnel that allows exactly files.pythonhosted.org:443.

It never terminates TLS: bytes are relayed untouched, so the client still verifies
the real certificate. Anything else gets 403. Bind 127.0.0.1 and expose it to the
host only through `ssh -R`, for the minutes the cache warm-up takes.
"""
import socket
import socketserver
import sys
import threading

ALLOWED = {("files.pythonhosted.org", 443)}


def pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while (block := src.recv(65536)):
            dst.sendall(block)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        line = self.rfile.readline(65536).decode("latin-1").strip()
        while self.rfile.readline(65536) not in (b"\r\n", b"\n", b""):
            pass
        parts = line.split(" ")
        if len(parts) < 2 or parts[0] != "CONNECT":
            self.wfile.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        host, _, port = parts[1].rpartition(":")
        if (host, int(port or 0)) not in ALLOWED:
            print("DENIED", parts[1], file=sys.stderr, flush=True)
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        upstream = socket.create_connection((host, 443), timeout=20)
        print("TUNNEL", parts[1], file=sys.stderr, flush=True)
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        self.wfile.flush()
        t = threading.Thread(target=pump, args=(upstream, self.connection), daemon=True)
        t.start()
        pump(self.connection, upstream)
        t.join()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    with Server(("127.0.0.1", port), Handler) as server:
        print(f"allowlist proxy on 127.0.0.1:{port} -> files.pythonhosted.org only", flush=True)
        server.serve_forever()
