"""Shared plumbing for the Fraud Ops app and the AI agents (stdlib only).

- SPIFFE: fetch this workload's X.509-SVID from the local SPIRE Agent and use it for mTLS
- HTTP:   tiny JSON client, plain or mTLS (verifying the peer's SPIFFE ID)
- Groq:   OpenAI-compatible chat completions with tool calling
"""
import calendar
import http.client
import json
import os
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

TRUST_DOMAIN = "ai-governance.demo"
SPIRE_SOCKET = "/run/spire/sockets/agent.sock"
SVID_DIR = "/svid"

APP_ID = f"spiffe://{TRUST_DOMAIN}/service/fraud-ops"
AGENT_PREFIX = f"spiffe://{TRUST_DOMAIN}/agent/"


def log(*parts):
    print(time.strftime("%H:%M:%S"), *parts, flush=True)


# ---------------------------------------------------------------- SPIFFE / SPIRE

_svid = {"id": None, "valid_after": 0, "valid_until": 0}


def _svid_time(line):
    # "SVID Valid Until:	2026-10-05 09:08:09 +0000 UTC"
    return calendar.timegm(time.strptime(line.split(":", 1)[1].strip()[:19], "%Y-%m-%d %H:%M:%S"))


def fetch_svid():
    """Ask the SPIRE Agent (Workload API) for this container's SVID and write it to SVID_DIR.
    The agent decides WHO we are from our Docker labels: we never choose our own identity."""
    os.makedirs(SVID_DIR, exist_ok=True)
    while True:
        p = subprocess.run(["spire-agent", "api", "fetch", "x509", "-socketPath", SPIRE_SOCKET, "-write", SVID_DIR],
                           capture_output=True, text=True)
        for line in p.stdout.splitlines():
            if line.startswith("SPIFFE ID:"):
                _svid["id"] = line.split(":", 1)[1].strip()
            elif line.startswith("SVID Valid After:"):
                _svid["valid_after"] = _svid_time(line)
            elif line.startswith("SVID Valid Until:"):
                _svid["valid_until"] = _svid_time(line)
        if p.returncode == 0 and _svid["id"]:
            return _svid["id"]
        log("waiting for SPIRE Agent:", (p.stderr or p.stdout).strip()[-160:])
        time.sleep(3)


def start_svid_rotation():
    """Renew the SVID once half its lifetime has passed. Checked against the wall clock every
    30 s, so a container that wakes up from a laptop sleep renews within seconds."""
    sid = fetch_svid()
    log("SPIRE issued SVID:", sid)

    def loop():
        while True:
            time.sleep(30)
            half_life = (_svid["valid_until"] - _svid["valid_after"]) / 2
            if time.time() > _svid["valid_until"] - half_life:
                fetch_svid()
                log("SVID renewed, valid until", time.strftime("%H:%M:%S", time.gmtime(_svid["valid_until"])), "UTC")

    threading.Thread(target=loop, daemon=True).start()
    return sid


def my_spiffe_id():
    return _svid["id"]


def _files():
    return f"{SVID_DIR}/svid.0.pem", f"{SVID_DIR}/svid.0.key", f"{SVID_DIR}/bundle.0.pem"


def client_context():
    cert, key, bundle = _files()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # SVIDs carry a SPIFFE ID, not a DNS name: we verify the ID ourselves
    ctx.load_verify_locations(bundle)
    ctx.load_cert_chain(cert, key)
    return ctx


_server_ctx = {"ctx": None, "mtime": 0}


def server_context():
    cert, key, bundle = _files()
    mtime = os.path.getmtime(cert)
    if mtime != _server_ctx["mtime"]:  # reload after rotation
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.load_verify_locations(bundle)
        ctx.verify_mode = ssl.CERT_REQUIRED  # mutual TLS: the caller must present an SVID too
        _server_ctx.update(ctx=ctx, mtime=mtime)
    return _server_ctx["ctx"]


def peer_spiffe_id(sock):
    cert = sock.getpeercert() or {}
    for kind, value in cert.get("subjectAltName", ()):
        if kind == "URI" and value.startswith(f"spiffe://{TRUST_DOMAIN}/"):
            return value
    return None


class MTLSServer(ThreadingHTTPServer):
    """HTTPS server that requires a client SVID. The handshake runs in the handler thread."""
    daemon_threads = True

    def get_request(self):
        sock, addr = self.socket.accept()
        return server_context().wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr


# ---------------------------------------------------------------- HTTP

def http_json(method, url, body=None, headers=None, form=False, timeout=20):
    headers = dict(headers or {})
    data = None
    if body is not None:
        data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"error": raw.decode(errors="replace")[:300]}
    except (urllib.error.URLError, OSError) as e:
        return 503, {"error": f"cannot reach {url}: {e}"}


def mtls_json(method, url, body=None, headers=None, expect_id=None, timeout=90):
    """Call another workload over mutual TLS, presenting our SVID and checking theirs."""
    u = urllib.parse.urlparse(url)
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=client_context(), timeout=timeout)
    try:
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        conn.request(method, u.path + (f"?{u.query}" if u.query else ""),
                     body=json.dumps(body) if body is not None else None, headers=hdrs)
        peer = peer_spiffe_id(conn.sock)
        if expect_id and peer != expect_id:
            return 495, {"error": f"server identity {peer} is not the expected {expect_id}"}
        r = conn.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw) if raw else {}
        except ValueError:
            return r.status, {"error": raw.decode(errors="replace")[:300]}
    except (OSError, ssl.SSLError) as e:
        return 503, {"error": f"cannot reach {url}: {e}"}
    finally:
        conn.close()


# ---------------------------------------------------------------- Groq (LLM)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def llm(messages, tools=None, temperature=0.2):
    """One chat completion. Returns the assistant message dict."""
    key = os.environ.get("GROQ_API_KEY", "").strip()
    if not key:
        return {"role": "assistant", "content": "The AI model is not configured: set GROQ_API_KEY in .env."}
    body = {"model": os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b"), "messages": messages,
            "temperature": temperature}
    if tools:
        body["tools"] = tools
    for attempt in range(4):
        code, res = http_json("POST", GROQ_URL, body, {"Authorization": f"Bearer {key}",
                                                        "User-Agent": "NexaBank-FraudOps/1.0"}, timeout=90)
        if code == 200:
            return res["choices"][0]["message"]
        if code in (429, 503) and attempt < 3:  # rate limited: back off and retry
            time.sleep(4 * (attempt + 1))
            continue
        return {"role": "assistant", "content": f"The AI model returned an error ({code}): {str(res)[:200]}"}
