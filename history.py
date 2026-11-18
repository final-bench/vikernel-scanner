"""Scan history for each signed-in user, kept in a PRIVATE dataset owned by whoever runs this Space.

Official Space: the VIDRAFT private dataset. A clone: set your own HF_TOKEN secret (write access) and the history is
kept in <your account>/vikernel-scanner-history, created private on first use. Without a token the history lives in
memory only and is lost when the Space restarts.
"""
import json, os, re, threading, time

TOKEN = os.environ.get("HF_TOKEN", "")
_repo = {"name": os.environ.get("VIKERNEL_HISTORY_REPO", "")}
_mem, _pending, _lock = {}, {}, threading.Lock()
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")
KEEP = 30  # newest scans listed per user

if TOKEN:
    from huggingface_hub import CommitOperationAdd, HfApi, hf_hub_download


def repo():
    """The private dataset that holds the history, created on first use."""
    if not TOKEN:
        return None
    if not _repo.get("ready"):
        api = HfApi(token=TOKEN)
        if not _repo["name"]:
            _repo["name"] = api.whoami()["name"] + "/vikernel-scanner-history"
        api.create_repo(_repo["name"], repo_type="dataset", private=True, exist_ok=True)
        _repo["ready"] = True
    return _repo["name"]


def where():
    return {"stored": "private dataset" if TOKEN else "memory only", "repo": _repo.get("name") or None}


def _summary(rep, sid, ts):
    return {"id": sid, "time": ts, "model": rep.get("model"), "grade": rep.get("grade"), "depth": rep.get("depth"),
            "counts": rep.get("counts"), "db_version": rep.get("db_version"), "checks": len(rep.get("probes") or []),
            "hits": (rep.get("firewall") or {}).get("hits")}


def save(user, sid, rep):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    u = _SAFE.sub("_", user)
    rec = {"summary": _summary(rep, sid, ts), "report": rep}
    with _lock:
        _mem.setdefault(u, {})[sid] = rec
        if TOKEN:
            _pending["history/%s/%s.json" % (u, sid)] = json.dumps(rec, ensure_ascii=False).encode()


def _flush_loop():
    while True:
        time.sleep(30)
        with _lock:
            ops = dict(_pending); _pending.clear()
        if not ops:
            continue
        try:
            HfApi(token=TOKEN).create_commit(repo(), [CommitOperationAdd(p, b) for p, b in ops.items()], commit_message="scan history", repo_type="dataset")
        except Exception:  # noqa: BLE001  keep them and retry
            with _lock:
                for p, b in ops.items():
                    _pending.setdefault(p, b)


def _load_user(u):
    """Bring a user's stored scans into memory once (after a restart)."""
    if not TOKEN or _mem.get(u, {}).get("__loaded__"):
        return
    try:
        api = HfApi(token=TOKEN)
        files = sorted(f for f in api.list_repo_files(repo(), repo_type="dataset") if f.startswith("history/%s/" % u))[-KEEP:]
        for f in files:
            rec = json.load(open(hf_hub_download(repo(), f, repo_type="dataset", token=TOKEN), encoding="utf-8"))
            _mem.setdefault(u, {}).setdefault(rec["summary"]["id"], rec)
    except Exception:  # noqa: BLE001
        return
    _mem.setdefault(u, {})["__loaded__"] = True


def list_for(user):
    u = _SAFE.sub("_", user)
    _load_user(u)
    rows = [r["summary"] for k, r in _mem.get(u, {}).items() if k != "__loaded__"]
    return sorted(rows, key=lambda r: r["time"], reverse=True)[:KEEP]


def get(user, sid):
    u = _SAFE.sub("_", user)
    _load_user(u)
    rec = _mem.get(u, {}).get(sid)
    return rec["report"] if rec and sid != "__loaded__" else None


if TOKEN:
    threading.Thread(target=_flush_loop, daemon=True).start()
