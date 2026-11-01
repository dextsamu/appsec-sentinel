#!/usr/bin/env python3
"""LABORATORIO: app finta con difetti di autorizzazione NOTI, solo per collaudare dynamic_authz_check.py.
Si lega solo a 127.0.0.1. Dati inventati. Non usare come esempio di codice."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKENS = {"tok-a": ("a", "user"), "tok-b": ("b", "user"), "tok-admin": ("root", "admin")}
ORDERS = {"1": "a", "2": "b"}


class H(BaseHTTPRequestHandler):
    def who(self):
        return TOKENS.get(self.headers.get("Authorization", "").replace("Bearer ", ""))

    def out(self, code, body="{}"):
        self.send_response(code); self.end_headers(); self.wfile.write(body.encode())

    def do_GET(self):
        u = self.who()
        p = self.path.split("?")[0]
        if p == "/api/health":
            return self.out(200)
        if p == "/api/me":
            return self.out(200 if u else 401)
        if p.startswith("/api/orders/"):               # DIFETTO NOTO: nessun controllo di proprietà (IDOR/BOLA)
            return self.out(200 if u else 401)
        if p == "/api/admin/users":                     # DIFETTO NOTO: nessun controllo di ruolo (BFLA)
            return self.out(200 if u else 401)
        if p == "/api/admin/audit":                     # corretto: solo admin
            return self.out(200 if u and u[1] == "admin" else (403 if u else 401))
        self.out(404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 0), H).serve_forever()
