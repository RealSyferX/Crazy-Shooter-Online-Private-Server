"""
HTTP Registration, Launcher API, and Live Status Web Server (default port 8080).

Compatible with CSO-Malaysia-Launcher-2.1.38.exe JSON contracts:
  - GET  /api/auth/registration-status?launcher=1
  - POST /api/auth/register  {"username":"...","password":"...","email":"..."}
  - GET  /api/news
  - GET  /api/status         (live server status JSON)
  - GET  /                   (clean local registration & status dashboard)
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .database import Database
from .realm import RealmServer

log = logging.getLogger("csg.http")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,24}$")

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>CSG Private Server</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:#0d1117; color:#e6edf3; margin:0; padding:32px; }
  .wrap { max-width:920px; margin:0 auto; display:grid; gap:20px; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:12px; padding:20px; }
  h1 { margin:0 0 6px; font-size:24px; }
  h2 { margin:0 0 12px; font-size:16px; color:#58a6ff; }
  .muted { color:#8b949e; font-size:14px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; }
  .stat { background:#0d1117; border:1px solid #21262d; border-radius:8px; padding:12px; }
  .stat b { font-size:22px; display:block; color:#3fb950; }
  form { display:grid; gap:10px; max-width:380px; }
  input, button { padding:10px 12px; border-radius:8px; border:1px solid #30363d; background:#0d1117; color:#e6edf3; font-size:14px; }
  button { background:#238636; border-color:#2ea043; cursor:pointer; font-weight:600; }
  button:hover { background:#2ea043; }
  pre { background:#0d1117; border:1px solid #21262d; border-radius:8px; padding:12px; overflow:auto; font-size:12px; }
  #msg { font-size:14px; min-height:20px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1 id="srvName">CSG Private Server</h1>
    <div class="muted" id="ann">Loading status...</div>
  </div>
  <div class="card">
    <h2>Live Status</h2>
    <div class="grid">
      <div class="stat"><span class="muted">Online Players</span><b id="onlineCount">0</b></div>
      <div class="stat"><span class="muted">Registered Accounts</span><b id="accCount">0</b></div>
      <div class="stat"><span class="muted">Active Rooms</span><b id="roomCount">0</b></div>
      <div class="stat"><span class="muted">Active Matches</span><b id="matchCount">0</b></div>
    </div>
  </div>
  <div class="card">
    <h2>Create Account</h2>
    <form id="regForm">
      <input name="username" placeholder="Username (3-24 chars)" required />
      <input name="password" type="password" placeholder="Password (min 4 chars)" required />
      <input name="email" type="email" placeholder="Email (optional)" />
      <button type="submit">Register Account</button>
    </form>
    <div id="msg"></div>
  </div>
  <div class="card">
    <h2>Active Rooms</h2>
    <pre id="roomsJson">[]</pre>
  </div>
</div>
<script>
async function refresh() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    document.getElementById('srvName').textContent = d.server_name;
    document.getElementById('ann').textContent = d.announcement + ' | Bishop :' + d.ports.bishop + ' | Realm :' + d.ports.realm;
    document.getElementById('onlineCount').textContent = d.realm.online_players;
    document.getElementById('accCount').textContent = d.accounts_count;
    document.getElementById('roomCount').textContent = d.realm.rooms.length;
    document.getElementById('matchCount').textContent = d.realm.active_matches;
    document.getElementById('roomsJson').textContent = JSON.stringify(d.realm.rooms, null, 2);
  } catch (e) {}
}
document.getElementById('regForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const body = Object.fromEntries(fd.entries());
  const res = await fetch('/api/auth/register', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
  });
  const data = await res.json();
  const el = document.getElementById('msg');
  el.style.color = res.ok ? '#3fb950' : '#f85149';
  el.textContent = data.message || JSON.stringify(data);
  if (res.ok) { ev.target.reset(); refresh(); }
});
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


class ApiHttpServer:
    def __init__(self, config: dict[str, Any], db: Database, realm: RealmServer):
        self.config = config
        self.db = db
        self.realm = realm
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        host = str(self.config.get("bind_host", "0.0.0.0"))
        port = int(self.config.get("http_port", 8080))
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                log.debug("[HTTP] " + fmt, *args)

            def _send_json(self, code: int, payload: dict[str, Any]) -> None:
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(raw)

            def _send_html(self, code: int, html: str) -> None:
                raw = html.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                path = urlparse(self.path).path
                if path in ("/", "/index.html"):
                    self._send_html(200, DASHBOARD_HTML)
                    return

                if path == "/api/auth/registration-status":
                    reg = parent.config.get("registration", {})
                    ev = parent.config.get("event", {})
                    cnt = parent.db.count_accounts()
                    max_acc = int(reg.get("max_accounts", 10000))
                    cap_enabled = bool(reg.get("cap_enabled", False))
                    remaining = max(0, max_acc - cnt) if cap_enabled else max_acc
                    available = bool(reg.get("enabled", True)) and (not cap_enabled or remaining > 0)
                    self._send_json(200, {
                        "available": available,
                        "remaining": remaining,
                        "registrationCapEnabled": cap_enabled,
                        "launcher": {
                            "announcement": str(reg.get("announcement", "")),
                            "maintenanceEnabled": bool(reg.get("maintenance_enabled", False)),
                            "maintenanceAllowGm": bool(reg.get("maintenance_allow_gm", True)),
                            "defaultCsp": int(parent.config.get("default_csp", 25000)),
                            "defaultGp": int(parent.config.get("default_gp", 500000)),
                            "event": {
                                "active": bool(ev.get("active", False)),
                                "expPercent": int(ev.get("exp_percent", 100)),
                                "gpPercent": int(ev.get("gp_percent", 100)),
                            },
                            "update": {
                                "enabled": False,
                                "latestVersion": "2.1.38",
                                "minimumVersion": "2.1.0",
                                "downloadUrl": "",
                                "sha256": "",
                                "notes": "",
                            },
                        },
                    })
                    return

                if path == "/api/news":
                    items = parent.db.list_news(limit=10)
                    self._send_json(200, {
                        "news": [
                            {
                                "id": it["news_id"],
                                "title": it["title"],
                                "content": it["content"],
                                "createdAt": it["created_at"],
                            }
                            for it in items
                        ]
                    })
                    return

                if path == "/api/status":
                    reg = parent.config.get("registration", {})
                    self._send_json(200, {
                        "server_name": parent.config.get("server_name", "CSG Private Server"),
                        "announcement": reg.get("announcement", ""),
                        "accounts_count": parent.db.count_accounts(),
                        "ports": {
                            "bishop": int(parent.config.get("bishop_port", 7451)),
                            "realm": int(parent.config.get("realm_port", 7452)),
                            "http": int(parent.config.get("http_port", 8080)),
                        },
                        "realm": parent.realm.get_status_snapshot(),
                    })
                    return

                self._send_json(404, {"message": "Not found"})

            def do_POST(self) -> None:
                path = urlparse(self.path).path
                if path != "/api/auth/register":
                    self._send_json(404, {"message": "Not found"})
                    return
                reg = parent.config.get("registration", {})
                if not reg.get("enabled", True):
                    self._send_json(403, {"message": "Registration is currently disabled."})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw = self.rfile.read(min(length, 16384))
                    body = json.loads(raw.decode("utf-8"))
                except Exception:
                    self._send_json(400, {"message": "Invalid JSON body."})
                    return

                username = str(body.get("username", "")).strip()
                password = str(body.get("password", ""))
                email = str(body.get("email", "")).strip()

                if not USERNAME_RE.match(username):
                    self._send_json(400, {"message": "Username must be 3-24 alphanumeric/underscore characters."})
                    return
                if len(password) < 4 or len(password) > 64:
                    self._send_json(400, {"message": "Password must be 4-64 characters."})
                    return
                if parent.db.get_account_by_username(username) is not None:
                    self._send_json(409, {"message": "Username already exists."})
                    return

                acc = parent.db.create_account(username, password, email)
                log.info("[HTTP] Registered new account user=%s id=%d", username, acc["account_id"])
                self._send_json(201, {
                    "message": f"Account '{username}' created successfully!",
                    "accountId": acc["account_id"],
                    "username": acc["username"],
                })

        self._httpd = ThreadingHTTPServer((host, port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="csg-http", daemon=True)
        self._thread.start()
        log.info("HTTP Registration & Status Server listening on http://%s:%d", host, port)

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
