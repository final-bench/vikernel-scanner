"""Master side. Active only on the official Space (VIKERNEL_MASTER=1 and a token that can read the private DB).

What the master controls for every copy of the scanner, including clones:
  - the check set (served per request, never shipped in the code)
  - the policy (on/off, minimum client version, blocked hosts, notice)
  - who scanned: the Hugging Face account and email behind every request
  - the official badge (only the master issues badge ids)
"""
import hashlib, hmac, json, os, secrets, threading, time, urllib.error, urllib.request

ENABLED = os.environ.get("VIKERNEL_MASTER") == "1" and bool(os.environ.get("HF_TOKEN"))
DB_REPO = os.environ.get("VIKERNEL_DB_REPO", "FINAL-Bench/vikernel-scanner-db")
BADGE_KEY = (os.environ.get("BADGE_KEY") or secrets.token_hex(16)).encode()
PER_USER_HOUR = int(os.environ.get("MASTER_CHECKS_PER_HOUR", "30"))
REFERENCE_USERS = {u.strip().lower() for u in os.environ.get("REFERENCE_USERS", "SeaWolf-AI,FINAL-Bench").split(",")}
_board = {"t": 0}
if ENABLED:  # import once, here: importing it first inside the flush thread races with the main thread
    from huggingface_hub import CommitOperationAdd, HfApi, hf_hub_download

_ids, _db, _pending, _hits, _badges = {}, {"t": 0}, {}, {}, {}
_lock = threading.Lock()


class Refuse(Exception):
    def __init__(self, code, msg):
        super().__init__(msg); self.code, self.msg = code, msg


def _api():
    return HfApi(token=os.environ["HF_TOKEN"])


def _get(path):
    return json.load(open(hf_hub_download(DB_REPO, path, repo_type="dataset", token=os.environ["HF_TOKEN"], force_download=True), encoding="utf-8"))


def _load_db():
    if time.time() - _db["t"] > 300:
        try:
            _db.update(policy=_get("policy.json"), free=_get("checkset/free.json"), t=time.time())
        except Exception:  # noqa: BLE001  keep the last good copy; refuse only if there never was one
            if "free" not in _db:
                raise Refuse(503, "The check database is not available right now.")
    return _db


def _identity(token):
    """Hugging Face account behind a token: OAuth tokens via userinfo, user access tokens via whoami-v2."""
    if not token:
        raise Refuse(401, "Sign in with Hugging Face first.")
    key = hashlib.sha256(token.encode()).hexdigest()
    c = _ids.get(key)
    if c and time.time() - c["t"] < 600:
        return c
    for url, name_k in (("https://huggingface.co/oauth/userinfo", "preferred_username"), ("https://huggingface.co/api/whoami-v2", "name")):
        try:
            j = json.loads(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token}), timeout=15).read())
        except (urllib.error.URLError, ValueError, TimeoutError):
            continue
        if j.get(name_k):
            c = {"user": j[name_k], "email": j.get("email"), "verified": bool(j.get("email_verified") or j.get("emailVerified")), "t": time.time()}
            _ids[key] = c
            if len(_ids) > 5000:
                _ids.clear()
            return c
    raise Refuse(401, "Hugging Face sign-in could not be verified. Sign in again.")


def _ver(v):
    try:
        return tuple(int(x) for x in str(v).split(".")[:3])
    except ValueError:
        return (0,)


def _queue(path, obj):
    with _lock:
        _pending[path] = json.dumps(obj, ensure_ascii=False, indent=1).encode()


def _flush_loop():
    while True:
        time.sleep(60)
        with _lock:
            ops = dict(_pending); _pending.clear()
        if not ops:
            continue
        try:
            _api().create_commit(DB_REPO, [CommitOperationAdd(p, b) for p, b in ops.items()], commit_message="scanner activity", repo_type="dataset")
        except Exception:  # noqa: BLE001  put them back and try again next round
            with _lock:
                for p, b in ops.items():
                    _pending.setdefault(p, b)


def _record_user(idn, host, version):
    path = "users/%s.json" % idn["user"]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rec = _ids.get("rec:" + idn["user"])
    if rec is None:
        try:
            rec = _get(path)
        except Exception:  # noqa: BLE001
            rec = {"user": idn["user"], "first_seen": now, "scans": 0, "hosts": []}
    rec.update(email=idn.get("email") or rec.get("email"), email_verified=idn.get("verified"), last_seen=now, client=version)
    if host not in rec["hosts"]:
        rec["hosts"] = (rec["hosts"] + [host])[-20:]
    _ids["rec:" + idn["user"]] = rec
    _queue(path, rec)
    return rec


def _gate(token, host, version):
    db = _load_db(); pol = db["policy"]; idn = _identity(token)
    if not pol.get("enabled", True):
        raise Refuse(503, (pol.get("notice") or {}).get("en") or "The scanner is paused by the maintainers.")
    if host in pol.get("blocked_hosts", []):
        raise Refuse(403, "This copy of the scanner is not allowed to use the ViKernel database.")
    if _ver(version) < _ver(pol.get("min_client", "0")):
        raise Refuse(426, "This scanner copy is out of date. Update it from github.com/final-bench/vikernel-scanner (minimum %s)." % pol.get("min_client"))
    now = time.time(); h = [t for t in _hits.get(idn["user"], []) if now - t < 3600]
    if len(h) >= PER_USER_HOUR:
        raise Refuse(429, "Hourly scan limit reached for this account. Try again later.")
    h.append(now); _hits[idn["user"]] = h
    return db, pol, idn


def handle(path, token, host, version, body=None):
    """Returns a JSON-able dict. Raises Refuse(code, message)."""
    if path == "/api/master/board":  # public
        return board()
    if path == "/api/master/catalog":  # public: what is checked, without the check text
        db = _load_db(); cs = db["free"]
        pol = db["policy"]
        return {"db_version": cs.get("version"), "controls": len(cs.get("controls", [])), "inventory": pol.get("inventory"),
                "checks": [{k: c.get(k) for k in ("id", "domain", "stage", "rule", "title")} for c in cs.get("checks", [])]}
    if path == "/api/master/checks":
        db, pol, idn = _gate(token, host, version)
        rec = _record_user(idn, host, version)
        return {"checkset": db["free"], "user": idn["user"], "has_email": bool(rec.get("email")),
                "policy": {"notice": pol.get("notice"), "latest_client": pol.get("latest_client"), "db_version": db["free"].get("version")}}
    if path == "/api/master/report":
        idn = _identity(token)
        b = body or {}
        bid = secrets.token_hex(6)
        day = time.strftime("%Y-%m-%d", time.gmtime())
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())  # full-second stamp so the board keeps the newest scan, not a random id
        rec = {"id": bid, "user": idn["user"], "host": host, "client": version, "date": day, "ts": ts, "model": str(b.get("model", ""))[:120],
               "grade": str(b.get("grade", "?"))[:1], "depth": b.get("depth"), "counts": b.get("counts"), "db_version": b.get("db_version"),
               "domains": {k: (v or {}).get("grade") for k, v in (b.get("domains") or {}).items()},
               "hit_checks": b.get("hit_checks"), "checks": b.get("checks"), "controls": b.get("controls"), "firewall": b.get("firewall"),
               "reference": idn["user"].lower() in REFERENCE_USERS}
        rec["sig"] = hmac.new(BADGE_KEY, json.dumps([bid, rec["model"], rec["grade"], day]).encode(), hashlib.sha256).hexdigest()[:24]
        _badges[bid] = rec
        _queue("scans/%s/%s.json" % (day, bid), rec)
        u = _ids.get("rec:" + idn["user"])
        if u:
            u["scans"] = int(u.get("scans", 0)) + 1; _queue("users/%s.json" % idn["user"], u)
        return {"badge": {"id": bid, "grade": rec["grade"], "url": "https://final-bench-vikernel-scanner.hf.space/badge/%s.svg" % bid}}
    raise Refuse(404, "not found")


def flush_now():
    """Write pending records at once (used by batch runs that exit right after)."""
    with _lock:
        ops = dict(_pending); _pending.clear()
    if ops:
        _api().create_commit(DB_REPO, [CommitOperationAdd(p, b) for p, b in ops.items()], commit_message="scanner activity", repo_type="dataset")


def board():
    """Public results: the latest scan of each model. No account names or emails, only whether it is a VIDRAFT reference scan."""
    if time.time() - _board["t"] < 300:
        return _board["v"]
    recs = list(_badges.values())
    try:
        have = {r["id"] for r in recs}
        files = sorted((f for f in _api().list_repo_files(DB_REPO, repo_type="dataset") if f.startswith("scans/") and f.endswith(".json")), reverse=True)[:400]
        for f in files:
            bid = f.rsplit("/", 1)[1][:-5]
            if bid not in have:
                r = _get(f); _badges[bid] = r; recs.append(r); have.add(bid)
    except Exception:  # noqa: BLE001
        pass
    latest = {}
    # Newest scan per model wins. Sort by the full timestamp; older records that predate the ts field
    # carry only a day, which sorts before any same-day ts, so a newer stamped scan always supersedes them.
    for r in sorted(recs, key=lambda r: (r.get("ts") or r.get("date", ""), r.get("id", ""))):
        if r.get("model") and r.get("checks"):
            latest[r["model"]] = r
    keep = ("id", "model", "grade", "depth", "domains", "hit_checks", "checks", "controls", "date", "reference", "db_version", "firewall")
    v = {"models": sorted(({k: r.get(k) for k in keep} for r in latest.values()), key=lambda r: ("ABCDF".find(r.get("grade") or "F"), r.get("hit_checks") or 0)),
         "scans": len(recs)}
    _board.update(v=v, t=time.time())
    return v


def badge(bid):
    """Official badge record for an id, or None."""
    if not all(c in "0123456789abcdef" for c in bid) or len(bid) != 12:
        return None
    if bid in _badges:
        return _badges[bid]
    try:
        for f in _api().list_repo_files(DB_REPO, repo_type="dataset"):
            if f.endswith("/%s.json" % bid):
                _badges[bid] = _get(f); return _badges[bid]
    except Exception:  # noqa: BLE001
        return None
    return None


if ENABLED:
    threading.Thread(target=_flush_loop, daemon=True).start()
