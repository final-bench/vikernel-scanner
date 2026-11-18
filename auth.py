"""Hugging Face sign-in for this Space (works the same on every clone: HF provides the OAuth app to each Space).

The access token is kept in server memory for the session only. It is sent to the ViKernel master so the master
can verify the account; it is never written to disk or logs.
"""
import base64, hashlib, hmac, json, os, secrets, time, urllib.parse, urllib.request

PROVIDER = os.environ.get("OPENID_PROVIDER_URL", "https://huggingface.co")
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
HOST = os.environ.get("SPACE_HOST", "")
SESS, STATES = {}, {}
TTL = 8 * 3600


def available():
    return bool(CLIENT_ID and CLIENT_SECRET and HOST)


_KEY = (os.environ.get("BADGE_KEY") or CLIENT_SECRET or secrets.token_hex(16)).encode()


def _state():
    t = str(int(time.time())) + "." + secrets.token_hex(6)
    return t + "." + hmac.new(_KEY, t.encode(), hashlib.sha256).hexdigest()[:20]


def _state_ok(st):
    try:
        ts, nonce, sig = st.split(".")
    except ValueError:
        return False
    good = hmac.new(_KEY, (ts + "." + nonce).encode(), hashlib.sha256).hexdigest()[:20]
    return hmac.compare_digest(good, sig) and 0 <= time.time() - int(ts) < 900


def login_url():
    st = _state()
    return PROVIDER + "/oauth/authorize?" + urllib.parse.urlencode({
        "client_id": CLIENT_ID, "redirect_uri": "https://%s/oauth/callback" % HOST, "scope": "openid profile email inference-api",
        "state": st, "response_type": "code"})


def callback(query):
    """Returns (session id, error)."""
    q = urllib.parse.parse_qs(query)
    code, st = (q.get("code") or [""])[0], (q.get("state") or [""])[0]
    if not code or not _state_ok(st):
        return None, "state"
    try:
        body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": "https://%s/oauth/callback" % HOST,
                                       "client_id": CLIENT_ID}).encode()
        auth = base64.b64encode(("%s:%s" % (CLIENT_ID, CLIENT_SECRET)).encode()).decode()
        tok = json.loads(urllib.request.urlopen(urllib.request.Request(PROVIDER + "/oauth/token", data=body, headers={
            "Authorization": "Basic " + auth, "Content-Type": "application/x-www-form-urlencoded"}), timeout=15).read())["access_token"]
        info = json.loads(urllib.request.urlopen(urllib.request.Request(PROVIDER + "/oauth/userinfo", headers={"Authorization": "Bearer " + tok}), timeout=15).read())
    except Exception:  # noqa: BLE001
        return None, "exchange"
    name = info.get("preferred_username")
    if not name:
        return None, "userinfo"
    sid = secrets.token_urlsafe(24)
    SESS[sid] = {"user": name, "email": bool(info.get("email")), "token": tok, "t": time.time()}
    for k in [k for k, s in SESS.items() if time.time() - s["t"] > TTL]:
        SESS.pop(k, None)
    return sid, None


def session(headers):
    for part in (headers.get("Cookie") or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "vks_sid" and v in SESS and time.time() - SESS[v]["t"] < TTL:
            return SESS[v]
    return None


def cookie(sid):
    return "vks_sid=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=None" % (sid, TTL)


def logout(headers):
    for part in (headers.get("Cookie") or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "vks_sid":
            SESS.pop(v, None)
    return "vks_sid=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None"
