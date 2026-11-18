"""ViKernel Scanner web app (free edition).

Sign-in with Hugging Face is required to scan. The check set comes from the ViKernel master for every scan.
The model's API key is used only for that scan. It stays in memory and is never stored or logged.
"""
import html, json, os, secrets, threading, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import auth, history
from scanner import engine, master, master_client

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "7860"))
MAX_ACTIVE = int(os.environ.get("MAX_ACTIVE_SCANS", "4"))
PER_IP = int(os.environ.get("SCANS_PER_10MIN", "6"))  # protects this server; not a product limit
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_TARGETS", "") == "1"  # only for a private install
CAUSES_URL = os.environ.get("CAUSES_URL", "https://final-bench-vikernel-redteam.hf.space/api/rt/leaderboard")
JOBS, HITS, LOCK = {}, {}, threading.Lock()
_causes = {"t": 0, "v": []}
_catalog = {}
GRADE_COLOR = {"A": "#22C55E", "B": "#84CC16", "C": "#F59E0B", "D": "#F97316", "F": "#EF4444"}


def causes():
    """Public names of the techniques found in the hackathon, shown as the full-scanner checklist."""
    if time.time() - _causes["t"] > 900:
        try:
            j = json.loads(urllib.request.urlopen(CAUSES_URL, timeout=8).read())
            _causes["v"] = [{"en": c.get("en"), "ko": c.get("ko")} for c in j.get("causes", []) if c.get("en")]
        except Exception:  # noqa: BLE001
            pass
        _causes["t"] = time.time()
    return _causes["v"]


def badge_svg(rec):
    g = rec.get("grade", "?") if rec else "?"
    label, val = "ViKernel Scan", ("grade " + g) if rec else "unknown"
    w1, w2 = 92, 70
    col = GRADE_COLOR.get(g, "#9CA3AF")
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">'
            '<rect width="%d" height="20" rx="3" fill="#232323"/><rect x="%d" width="%d" height="20" rx="3" fill="%s"/>'
            '<rect x="%d" width="6" height="20" fill="%s"/>'
            '<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
            '<text x="%d" y="14">%s</text><text x="%d" y="14">%s</text></g></svg>') % (
        w1 + w2, label, val, w1 + w2, w1, w2, col, w1, col, w1 // 2, html.escape(label), w1 + w2 // 2, html.escape(val))


def run_job(jid, token, base_url, model, key, user=None):
    job = JOBS[jid]
    try:
        engine.check_target(base_url, allow_private=ALLOW_PRIVATE)
        checkset, policy = master_client.get_checkset(token)
        job["notice"] = (policy or {}).get("notice")
        hf_router = urllib.parse.urlparse(base_url).hostname in ("router.huggingface.co", "api-inference.huggingface.co")
        target = engine.Target(base_url, model, key or (token if hf_router else ""))  # HF router without a key: run on the signed-in account

        def on_event(e):
            job["events"].append(e); job["progress"] = (e["i"] - (1 if e["type"] == "start" else 0), e["n"])
        rep = engine.run_scan(target, checkset, on_event)
        summ = {k: rep.get(k) for k in ("model", "grade", "depth", "counts", "domains", "db_version", "version", "hit_checks", "controls")}
        summ["checks"] = len(rep.get("probes") or []); summ["firewall"] = {k: (rep.get("firewall") or {}).get(k) for k in ("hits", "blocked", "grade_after")}
        rep["badge"] = master_client.report(token, summ)
        job["report"] = rep; job["status"] = "done"
        if user:
            history.save(user, jid, rep)
    except Exception as e:  # noqa: BLE001
        msg = str(e)[:240]
        if "402" in msg:
            msg += " | This Hugging Face account has no inference credit. Sign in with an account that has credit, or enter a key for another endpoint."
        elif "401" in msg or "403" in msg:
            msg += " | The model endpoint refused the key. For the Hugging Face router, sign out and sign in again (the sign-in now includes model access), or enter your own token."
        job["status"] = "error"; job["error"] = msg
    finally:
        job["ended"] = time.time()


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj, ctype="application/json", extra=None):
        b = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ("json" in ctype or "html" in ctype) else ""))
        self.send_header("Content-Length", str(len(b))); self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)

    def _redirect(self, to, cookie=None):
        self.send_response(302); self.send_header("Location", to)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0"); self.end_headers()

    def _ip(self):
        return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

    def _master(self, path, body=None):
        tok = (self.headers.get("Authorization") or "").replace("Bearer ", "", 1).strip()
        try:
            return self._send(200, master.handle(path, tok, self.headers.get("X-VKS-Host", "?")[:120], self.headers.get("X-VKS-Version", "0"), body))
        except master.Refuse as e:
            return self._send(e.code, {"error": e.msg})

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            return self._send(200, open(os.path.join(HERE, "index.html"), "rb").read(), "text/html")
        if p == "/login":
            return self._redirect(auth.login_url()) if auth.available() else self._send(503, {"error": "Sign-in is not configured on this copy."})
        if p == "/oauth/callback":
            sid, err = auth.callback(self.path.split("?", 1)[1] if "?" in self.path else "")
            return self._redirect("/?login=ok", auth.cookie(sid)) if sid else self._redirect("/?login=" + err)
        if p == "/logout":
            return self._redirect("/", auth.logout(self.headers))
        if p == "/api/me":
            s = auth.session(self.headers)
            return self._send(200, {"user": s["user"] if s else None, "email": s["email"] if s else None, "signin": auth.available()})
        if p == "/api/history" or p.startswith("/api/history/"):
            s = auth.session(self.headers)
            if not s:
                return self._send(401, {"error": "Sign in with Hugging Face first.", "login": True})
            if p == "/api/history":
                return self._send(200, {"scans": history.list_for(s["user"]), **history.where()})
            r = history.get(s["user"], p.rsplit("/", 1)[1])
            return self._send(200, r) if r else self._send(404, {"error": "not found"})
        if p == "/api/info":
            return self._send(200, {"version": engine.VERSION, "master": master_client.MASTER_URL, "is_master": master.ENABLED,
                                    "domains": {k: {"en": v[0], "ko": v[1]} for k, v in engine.DOMAINS.items()}, "causes": causes()})
        if p.startswith("/api/scan/"):
            job = JOBS.get(p.rsplit("/", 1)[1])
            if not job:
                return self._send(404, {"error": "unknown scan"})
            return self._send(200, {k: job.get(k) for k in ("status", "progress", "error", "report", "notice")} | {"events": job["events"][-12:]})
        if p in ("/api/master/checks", "/api/master/catalog", "/api/master/board") and master.ENABLED:
            return self._master(p)
        if p == "/api/board":
            b = master_client.board()
            return self._send(200 if b else 503, b or {"error": "board unavailable"})
        if p == "/api/catalog":
            c = _catalog.get("v") if time.time() - _catalog.get("t", 0) < 300 else None
            if c is None:
                c = master_client.catalog(); _catalog.update(v=c, t=time.time())
            return self._send(200 if c else 503, c or {"error": "catalog unavailable"})
        if p.startswith("/badge/") and p.endswith(".svg") and master.ENABLED:
            return self._send(200, badge_svg(master.badge(p[7:-4])).encode(), "image/svg+xml", {"Cache-Control": "max-age=3600"})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > 8192:
            return self._send(413, {"error": "too large"})
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad request"})
        if p == "/api/master/report" and master.ENABLED:
            return self._master(p, req)
        if p != "/api/scan":
            return self._send(404, {"error": "not found"})
        s = auth.session(self.headers)
        if not s:
            return self._send(401, {"error": "Sign in with Hugging Face first.", "login": True})
        base, model, key = str(req.get("base_url", "")).strip(), str(req.get("model", "")).strip(), str(req.get("api_key", "")).strip()
        if not base or not req.get("consent"):
            return self._send(400, {"error": "Endpoint and the confirmation are required."})
        ip, now = self._ip(), time.time()
        with LOCK:
            for k in [k for k, j in JOBS.items() if j.get("ended") and now - j["ended"] > 1800]:
                JOBS.pop(k, None)
            h = [t for t in HITS.get(ip, []) if now - t < 600]
            if len(h) >= PER_IP:
                return self._send(429, {"error": "Too many scans from this address. Try again in a few minutes."})
            if sum(1 for j in JOBS.values() if j["status"] == "running") >= MAX_ACTIVE:
                return self._send(429, {"error": "The scanner is busy. Try again in a minute."})
            h.append(now); HITS[ip] = h
            jid = secrets.token_urlsafe(12)
            JOBS[jid] = {"status": "running", "events": [], "progress": (0, 1), "started": now}
        threading.Thread(target=run_job, args=(jid, s["token"], base, model, key, s["user"]), daemon=True).start()
        self._send(200, {"id": jid})

    def log_message(self, *a):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
