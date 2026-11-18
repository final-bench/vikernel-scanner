"""Talks to the ViKernel master server.

Every copy of this app, including clones, gets its check set, its policy and its badges from the master.
The check set is not stored in this repository. The master needs the signed-in user's Hugging Face token.
"""
import json, os, urllib.error, urllib.request

from . import engine

MASTER_URL = os.environ.get("VIKERNEL_MASTER_URL", "https://final-bench-vikernel-scanner.hf.space").rstrip("/")
HOST = os.environ.get("SPACE_HOST", "local-cli")


class MasterError(RuntimeError):
    pass


def _local():
    try:
        from . import master  # present and enabled only on the master Space
        return master if master.ENABLED else None
    except ImportError:
        return None


def _call(path, token, body=None):
    m = _local()
    if m is not None:
        try:
            return m.handle(path, token, HOST, engine.VERSION, body)
        except m.Refuse as e:
            raise MasterError(e.msg)
    h = {"Authorization": "Bearer " + token, "X-VKS-Host": HOST, "X-VKS-Version": engine.VERSION, "Content-Type": "application/json"}
    req = urllib.request.Request(MASTER_URL + path, data=json.dumps(body).encode() if body is not None else None, headers=h,
                                 method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error")
        except Exception:  # noqa: BLE001
            msg = None
        raise MasterError(msg or "The ViKernel master refused the request (HTTP %d)." % e.code)
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise MasterError("The ViKernel master is not reachable: %s" % str(e)[:80])


def catalog():
    """Public list of checks (ids, domains, stages, titles). No sign-in needed."""
    try:
        return _call("/api/master/catalog", "")
    except MasterError:
        return None


def get_checkset(token):
    """Returns (checkset, policy). Raises MasterError when the master says no."""
    j = _call("/api/master/checks", token)
    return j["checkset"], j.get("policy", {})


def report(token, summary):
    """Sends the scan summary. Returns the official badge record from the master, or None."""
    try:
        return _call("/api/master/report", token, summary).get("badge")
    except MasterError:
        return None
