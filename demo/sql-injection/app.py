from __future__ import annotations

import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

DATABASE = sqlite3.connect("/tmp/demo.db", check_same_thread=False)
DATABASE.execute("CREATE TABLE users(username TEXT PRIMARY KEY,password TEXT NOT NULL)")
DATABASE.executemany(
    "INSERT INTO users(username,password) VALUES(?,?)",
    (("admin", "demo-admin-42"), ("alice", "demo-alice-17"), ("bob", "demo-bob-93")),
)
DATABASE.commit()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        request = urlsplit(self.path)
        if request.path == "/health":
            self.send({"status": "vulnerable-demo"})
            return
        if request.path != "/login":
            self.send({"usage": "/login?username=alice&password=demo-alice-17"}, 404)
            return
        values = parse_qs(request.query, keep_blank_values=True)
        username = values.get("username", [""])[0]
        password = values.get("password", [""])[0]
        # Deliberately vulnerable for the isolated LaTaupe demonstration.
        statement = (
            "SELECT username,password FROM users "
            f"WHERE username='{username}' AND password='{password}'"
        )
        try:
            rows = DATABASE.execute(statement).fetchall()
            self.send({"authenticated": bool(rows), "accounts": rows, "query": statement})
        except sqlite3.Error as error:
            self.send({"error": str(error), "query": statement}, 400)

    def log_message(self, *_: object) -> None:
        return

    def send(self, value: object, status: int = 200) -> None:
        payload = json.dumps(value, ensure_ascii=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


ThreadingHTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
