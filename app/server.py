"""NexaBank Fraud Ops: the bank application (stdlib only).

Two listeners, one API:
  :8000  HTTP  for people    - identity = Keycloak login (OIDC authorization-code flow, session cookie)
  :8443  mTLS  for AI agents - identity = the agent's SPIFFE ID (from its X.509-SVID)
                               + optionally the human it works for (Keycloak access token)

Every protected operation goes through decide_many(), which uses one of two engines (AUTHZ_MODE in .env):
  legacy   the bank's original role checks, hard-coded below (what Risk & Compliance flagged)
  openfga  OpenFGA decides: BatchCheck / ListObjects against FGA_STORE_ID
"""
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
from collections import deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from common import (AGENT_PREFIX, MTLSServer, http_json, log, mtls_json, my_spiffe_id, peer_spiffe_id,
                    start_svid_rotation)

# ---------------------------------------------------------------- configuration (.env)

env = os.environ.get
AUTHZ_MODE = env("AUTHZ_MODE", "legacy").strip().lower()
FGA_API_URL = env("FGA_API_URL", "http://openfga:8090").rstrip("/")
FGA_STORE_ID = env("FGA_STORE_ID", "").strip()
FGA_MODEL_ID = env("FGA_MODEL_ID", "").strip()          # empty = latest model in the store
FGA_SYNC_KEYCLOAK_GROUPS = env("FGA_SYNC_KEYCLOAK_GROUPS", "false").strip().lower() == "true"
FGA_ON_BEHALF_OF = env("FGA_ON_BEHALF_OF", "false").strip().lower() == "true"

KC_INTERNAL = env("KEYCLOAK_URL", "http://keycloak:8080")
KC_PUBLIC = env("KEYCLOAK_PUBLIC_URL", "http://localhost:8180")
REALM = "nexabank"
CLIENT_ID = env("KEYCLOAK_CLIENT_ID", "nexabank-app")
CLIENT_SECRET = env("KEYCLOAK_CLIENT_SECRET", "nexabank-app-secret")
APP_URL = env("APP_PUBLIC_URL", "http://localhost:8000")
ORCHESTRATOR_URL = "https://agent-orchestrator:8443"
AGENT_URLS = {n: f"https://agent-{n}:8443" for n in ("orchestrator", "research", "payment")}

ACTIVITY = deque(maxlen=300)
SESSIONS = {}
PENDING_LOGINS = {}

# ---------------------------------------------------------------- data (SQLite)

db = sqlite3.connect("/data/nexabank.db", check_same_thread=False)
db.row_factory = sqlite3.Row
db_lock = threading.Lock()


def q(sql, args=(), one=False):
    with db_lock:
        cur = db.execute(sql, args)
        db.commit()
        rows = [dict(r) for r in cur.fetchall()]
    return (rows[0] if rows else None) if one else rows


def init_db():
    db.executescript("""
      CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, title, customer, customer_id, exposure INTEGER,
        team, lead, status, opened, summary);
      CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY, case_id, title, uploaded_by, body,
        archived INTEGER DEFAULT 0, uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP);
      CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, case_id, title, prepared_by, status, body, approved_by);
      CREATE TABLE IF NOT EXISTS transactions(case_id, time, merchant, mcc, amount INTEGER, channel, device, location);
      CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT, case_id, amount INTEGER, reason,
        requested_by, executed_by, at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    if q("SELECT COUNT(*) n FROM cases", one=True)["n"]:
        return
    with open("bank_data.json", encoding="utf-8") as f:
        data = json.load(f)
    for table, rows in data.items():
        for r in rows:
            q(f"INSERT INTO {table}({','.join(r)}) VALUES({','.join('?' * len(r))})", tuple(r.values()))
    log("seeded bank data")


# ---------------------------------------------------------------- Keycloak (authentication)

_userinfo_cache = {}


def keycloak_userinfo(token):
    """Validate an access token with Keycloak and return its claims (cached for 60 s)."""
    hit = _userinfo_cache.get(token)
    if hit and hit[0] > time.time():
        return hit[1]
    code, info = http_json("GET", f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/userinfo",
                           headers={"Authorization": f"Bearer {token}"})
    if code != 200:
        return None
    _userinfo_cache[token] = (time.time() + 60, info)
    return info


def user_from_claims(info):
    return {"id": "user:" + info["preferred_username"], "username": info["preferred_username"],
            "name": info.get("name") or info["preferred_username"], "groups": sorted(info.get("groups", [])),
            "roles": sorted(r for r in info.get("roles", []) if not r.startswith("default-roles")
                            and r not in ("offline_access", "uma_authorization"))}


def session_token(s):
    """Current access token of a browser session, refreshed shortly before it expires."""
    if not s:
        return None
    if s["expires"] - time.time() < 30:
        code, tok = http_json("POST", f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/token",
                              {"grant_type": "refresh_token", "refresh_token": s["refresh"],
                               "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}, form=True)
        if code != 200:
            return None
        s.update(access=tok["access_token"], refresh=tok.get("refresh_token", s["refresh"]),
                 expires=time.time() + tok.get("expires_in", 300))
    return s["access"]


# ---------------------------------------------------------------- OpenFGA client

def fga(path, body):
    if not FGA_STORE_ID:
        return 400, {"message": "FGA_STORE_ID is not set in .env"}
    if FGA_MODEL_ID and path in ("batch-check", "check", "list-objects", "list-users", "expand", "write"):
        body = {**body, "authorization_model_id": FGA_MODEL_ID}
    return http_json("POST", f"{FGA_API_URL}/stores/{FGA_STORE_ID}/{path}", body)


def fga_batch(checks):
    """[(user, relation, object, context)] -> [(allowed, reason)] in one BatchCheck call."""
    body = {"checks": [{"tuple_key": {"user": u, "relation": r, "object": o}, "context": c or {},
                        "correlation_id": str(i)} for i, (u, r, o, c) in enumerate(checks)]}
    code, res = fga("batch-check", body)
    if code != 200:  # OpenFGA unreachable, or the model doesn't define this yet: fail closed
        return [(False, f"OpenFGA: {res.get('message') or res.get('error')}")] * len(checks)
    out = []
    for i in range(len(checks)):
        r = res.get("result", {}).get(str(i), {})
        err = (r.get("error") or {}).get("message")
        out.append((r.get("allowed") is True, f"OpenFGA: {err}" if err else "OpenFGA Check"))
    return out


def fga_list(user, relation, type_, context=None):
    code, res = fga("list-objects", {"user": user, "relation": relation, "type": type_, "context": context or {}})
    return {o.split(":", 1)[1] for o in res.get("objects", [])} if code == 200 else set()


def fga_write(writes=(), deletes=()):
    body = {}
    if writes:
        body["writes"] = {"tuple_keys": list(writes), "on_duplicate": "ignore"}
    if deletes:
        body["deletes"] = {"tuple_keys": list(deletes), "on_missing": "ignore"}
    return fga("write", body)


def note(kind, engine, who, status, **extra):
    ACTIVITY.appendleft({"time": time.strftime("%H:%M:%S"), "kind": kind, "engine": engine, "who": who,
                         "status": status, **extra})
    log(f"[{engine}] {who}: {status}")


def sync_keycloak_groups(user):
    """Keycloak is the source of truth for group membership: mirror it into OpenFGA at every login."""
    if AUTHZ_MODE != "openfga" or not FGA_SYNC_KEYCLOAK_GROUPS:
        return
    code, res = fga("read", {"tuple_key": {"user": user["id"], "relation": "member", "object": "group:"}})
    if code != 200:
        return note("sync", "Keycloak → OpenFGA", user["id"], f"sync failed: {res.get('message') or res.get('error')}")
    have = {t["key"]["object"] for t in res.get("tuples", [])}
    want = {"group:" + g.lower() for g in user["groups"]}
    add = [{"user": user["id"], "relation": "member", "object": o} for o in sorted(want - have)]
    remove = [{"user": user["id"], "relation": "member", "object": o} for o in sorted(have - want)]
    if not (add or remove):
        return note("sync", "Keycloak → OpenFGA", user["id"], "group memberships already in sync")
    code, res = fga_write(add, remove)
    note("sync", "Keycloak → OpenFGA", user["id"], "synced" if code == 200 else f"failed: {res.get('message')}",
         added=[f"{t['user']} member {t['object']}" for t in add],
         removed=[f"{t['user']} member {t['object']}" for t in remove])


# ---------------------------------------------------------------- authorization

def legacy_rule(user, agent, relation, obj):
    """NexaBank's ORIGINAL access control, hard-coded in the app. Risk & Compliance flagged all of it."""
    if agent:
        return True, "legacy: every AI agent runs as the trusted 'ai-service' account"   # F3, F4
    roles = user["roles"]
    if "admin" in roles:
        return True, "legacy: role 'admin' may do everything"                             # F2
    kind = obj.split(":")[0]
    if kind == "dashboard":
        return False, "legacy: role 'admin' required"
    if kind == "tool":
        return ("manager" in roles), "legacy: role 'manager' required for payments"
    if "ai-reviewer" in roles and kind != "report":
        return False, "legacy: role 'ai-reviewer' may only open reports"
    if "employee" in roles:
        return True, "legacy: role 'employee' may open every case, file and report"       # F1, F2
    return False, "legacy: role 'employee' required"


def principals(user, agent):
    """Who must be authorized. An agent acting for a human is the confused-deputy case (F4)."""
    if agent and user:
        return [agent, user["id"]] if FGA_ON_BEHALF_OF else [agent]
    return [agent or user["id"]]


def decide_many(user, agent, items):
    """items: [(relation, object, context)] -> [(allowed, [{principal, allowed, reason}])]"""
    if AUTHZ_MODE != "openfga":
        out = []
        for rel, obj, _ in items:
            ok, why = legacy_rule(user, agent, rel, obj)
            out.append((ok, [{"principal": agent or user["id"], "allowed": ok, "reason": why}]))
        return out
    who = principals(user, agent)
    res = fga_batch([(p, rel, obj, ctx) for rel, obj, ctx in items for p in who]) if items else []
    out = []
    for i in range(len(items)):
        checks = [{"principal": p, "allowed": res[i * len(who) + j][0], "reason": res[i * len(who) + j][1]}
                  for j, p in enumerate(who)]
        out.append((all(c["allowed"] for c in checks), checks))
    return out


class Denied(Exception):
    def __init__(self, status, payload):
        super().__init__(payload.get("error"))
        self.status, self.payload = status, payload


def guard(ctx, action, relation, obj, context=None):
    """Authorize one operation, record it in the activity log, raise Denied if it is not allowed."""
    allowed, checks = decide_many(ctx["user"], ctx["agent"], [(relation, obj, context)])[0]
    entry = {"time": time.strftime("%H:%M:%S"), "kind": "decision",
             "engine": "OpenFGA" if AUTHZ_MODE == "openfga" else "Legacy roles",
             "channel": ctx["channel"], "action": action, "relation": relation, "resource": obj,
             "context": context or {}, "checks": checks, "decision": "ALLOWED" if allowed else "DENIED",
             "acting_for": ctx["user"]["id"] if ctx["agent"] and ctx["user"] else None,
             "caller": ctx["agent"] or ctx["user"]["id"]}
    ACTIVITY.appendleft(entry)
    who = entry["caller"] + (f" for {entry['acting_for']}" if entry["acting_for"] else "")
    log(f"[{entry['engine']}] {who:<38} {action:<20} {obj:<22} {entry['decision']}")
    if not allowed:
        raise Denied(403, {"error": f"Not authorized to {action} ({obj})", "decision": entry})
    return entry


def list_visible(ctx, relation, type_, sql):
    """Rows of a type the caller may see. OpenFGA: ListObjects, intersected for agent + human."""
    rows = q(sql)
    if AUTHZ_MODE != "openfga":
        ok = [r for r in rows if legacy_rule(ctx["user"], ctx["agent"], relation, f"{type_}:{r['id']}")[0]]
        return ok, {"call": "legacy role check", "query": f"{relation} on every {type_}", "result": len(ok)}
    ids = None
    who = principals(ctx["user"], ctx["agent"])
    for p in who:
        found = fga_list(p, relation, type_)
        ids = found if ids is None else ids & found
    ok = [r for r in rows if r["id"] in ids]
    return ok, {"call": "ListObjects", "query": " ∩ ".join(f"{p} {relation} {type_}:*" for p in who),
                "result": ", ".join(r["id"] for r in ok) or "none"}


# ---------------------------------------------------------------- API

def api_session(ctx, m, b):
    return 200, {"user": ctx["user"], "mode": AUTHZ_MODE, "on_behalf_of": FGA_ON_BEHALF_OF,
                 "sync": FGA_SYNC_KEYCLOAK_GROUPS, "store": FGA_STORE_ID, "model": FGA_MODEL_ID or "latest",
                 "app_svid": my_spiffe_id()}


def api_home(ctx, m, b):
    cases, t1 = list_visible(ctx, "can_view", "case", "SELECT id, title, customer, status, exposure FROM cases ORDER BY id")
    reviews, t2 = list_visible(ctx, "can_approve", "report",
                               "SELECT id, title, case_id, prepared_by, status FROM reports ORDER BY id")
    reviews = [r for r in reviews if r["status"] == "Awaiting approval"]
    admin = decide_many(ctx["user"], None, [("can_view", "dashboard:admin", None)])[0][0]
    return 200, {"cases": cases, "reviews": reviews, "admin": admin, "trace": [t1, t2]}


def api_cases(ctx, m, b):
    cases, trace = list_visible(ctx, "can_view", "case", "SELECT id, title, customer, status, exposure, team FROM cases ORDER BY id")
    return 200, {"cases": cases, "trace": trace}


def api_case(ctx, m, b):
    case_id = m.group(1)
    case = q("SELECT * FROM cases WHERE id=?", (case_id,), one=True)
    if not case:
        return 404, {"error": f"no case {case_id}"}
    d = guard(ctx, "open case", "can_view", f"case:{case_id}")
    docs = q("SELECT id, title, uploaded_by, archived, uploaded_at FROM documents WHERE case_id=? ORDER BY uploaded_at, id", (case_id,))
    reports = q("SELECT * FROM reports WHERE case_id=?", (case_id,))
    payments = q("SELECT * FROM payments WHERE case_id=? ORDER BY id DESC", (case_id,))
    items = [(rel, f"document:{x['id']}", None) for x in docs for rel in ("can_view", "can_delete")]
    items += [("can_approve", f"report:{r['id']}", None) for r in reports]
    items += [("can_execute", "tool:payment", {"amount": 1})]
    res = decide_many(ctx["user"], ctx["agent"], items)
    can = {f"{rel}|{obj}": ok for (rel, obj, _), (ok, _) in zip(items, res)}
    for x in docs:
        x["can_view"], x["can_delete"] = can[f"can_view|document:{x['id']}"], can[f"can_delete|document:{x['id']}"]
    for r in reports:
        r["can_approve"] = can[f"can_approve|report:{r['id']}"]
    trace = [{"call": "BatchCheck" if AUTHZ_MODE == "openfga" else "legacy role check",
              "query": f"{' + '.join(c['principal'] for c in checks)} {rel} {obj}", "allowed": ok}
             for (rel, obj, _), (ok, checks) in zip(items, res)]
    return 200, {"case": case, "documents": docs, "reports": reports, "payments": payments,
                 "can_reimburse": can["can_execute|tool:payment"], "decision": d, "trace": trace}


def api_transactions(ctx, m, b):
    d = guard(ctx, "read transactions", "can_view", f"case:{m.group(1)}")
    return 200, {"transactions": q("SELECT * FROM transactions WHERE case_id=? ORDER BY time", (m.group(1),)), "decision": d}


def api_document(ctx, m, b):
    doc = q("SELECT * FROM documents WHERE id=?", (m.group(1),), one=True)
    if not doc:
        return 404, {"error": f"no document {m.group(1)}"}
    d = guard(ctx, "read document", "can_view", f"document:{doc['id']}")
    return 200, {**doc, "decision": d}


def api_upload(ctx, m, b):
    case_id = m.group(1)
    if not q("SELECT id FROM cases WHERE id=?", (case_id,), one=True):
        return 404, {"error": f"no case {case_id}"}
    d = guard(ctx, "upload document", "can_view", f"case:{case_id}")
    title, body = (b.get("title") or "").strip()[:120], (b.get("body") or "").strip()[:5000]
    if not title or not body:
        return 400, {"error": "title and body are required"}
    doc_id = f"doc-{secrets.token_hex(3)}"
    uploader = ctx["user"]["username"] if ctx["user"] else ctx["agent"]
    q("INSERT INTO documents(id, case_id, title, uploaded_by, body) VALUES(?,?,?,?,?)", (doc_id, case_id, title, uploader, body))
    status = "legacy mode: nothing to record"
    if AUTHZ_MODE == "openfga":  # the app records the new facts in OpenFGA as part of the business operation
        writes = [{"user": f"case:{case_id}", "relation": "parent", "object": f"document:{doc_id}"}]
        if ctx["user"]:
            writes.append({"user": ctx["user"]["id"], "relation": "owner", "object": f"document:{doc_id}"})
        code, res = fga_write(writes)
        status = ("wrote " + "; ".join(f"{w['user']} {w['relation']} {w['object']}" for w in writes)) if code == 200 \
            else f"OpenFGA write failed: {res.get('message')}"
        note("write", "App → OpenFGA", uploader, status)
    return 201, {"id": doc_id, "tuples": status, "decision": d}


def api_archive(ctx, m, b):
    doc = q("SELECT id FROM documents WHERE id=?", (m.group(1),), one=True)
    if not doc:
        return 404, {"error": f"no document {m.group(1)}"}
    d = guard(ctx, "archive document", "can_delete", f"document:{doc['id']}")
    q("UPDATE documents SET archived=1 WHERE id=?", (doc["id"],))
    return 200, {"message": "Document archived (bank records are retained, never destroyed)", "decision": d}


def api_approve(ctx, m, b):
    rep = q("SELECT * FROM reports WHERE id=?", (m.group(1),), one=True)
    if not rep:
        return 404, {"error": f"no report {m.group(1)}"}
    d = guard(ctx, "approve report", "can_approve", f"report:{rep['id']}")
    who = ctx["user"]["username"] if ctx["user"] else ctx["agent"]
    q("UPDATE reports SET status='Approved and filed', approved_by=? WHERE id=?", (who, rep["id"]))
    return 200, {"message": f"{rep['title']} {rep['id']} approved by {who} and filed with the regulator", "decision": d}


def api_reimburse(ctx, m, b):
    case_id = m.group(1)
    if not q("SELECT id FROM cases WHERE id=?", (case_id,), one=True):
        return 404, {"error": f"no case {case_id}"}
    try:
        amount = int(b.get("amount"))
    except (TypeError, ValueError):
        return 400, {"error": "amount (whole rupees) is required"}
    if amount <= 0:
        return 400, {"error": "amount must be positive"}
    d = guard(ctx, f"reimburse ₹{amount:,}", "can_execute", "tool:payment", {"amount": amount})
    q("INSERT INTO payments(case_id, amount, reason, requested_by, executed_by) VALUES(?,?,?,?,?)",
      (case_id, amount, (b.get("reason") or "")[:200], ctx["user"]["username"] if ctx["user"] else "-",
       ctx["agent"] or ctx["user"]["id"]))
    return 200, {"message": f"₹{amount:,} reimbursed to the customer of {case_id}", "decision": d}


def api_admin(ctx, m, b):
    d = guard(ctx, "open admin console", "can_view", "dashboard:admin")
    agents = []
    for name, url in AGENT_URLS.items():
        code, res = mtls_json("GET", f"{url}/health", expect_id=AGENT_PREFIX + name, timeout=5)
        agents.append({"name": name, "spiffe_id": AGENT_PREFIX + name, "online": code == 200,
                       "detail": res.get("status") or res.get("error")})
    try:
        with open("/shared/spire-entries.json") as f:
            entries = [f"spiffe://{e['spiffe_id']['trust_domain']}{e['spiffe_id']['path']}" for e in json.load(f).get("entries", [])]
    except (OSError, ValueError):
        entries = []
    return 200, {"decision": d, "agents": agents, "spire_entries": sorted(e for e in entries if "/node/" not in e),
                 "counts": {t: q(f"SELECT COUNT(*) n FROM {t}", one=True)["n"] for t in ("cases", "documents", "reports", "payments")},
                 "config": {"AUTHZ_MODE": AUTHZ_MODE, "FGA_STORE_ID": FGA_STORE_ID or "-", "FGA_MODEL_ID": FGA_MODEL_ID or "latest",
                            "FGA_SYNC_KEYCLOAK_GROUPS": FGA_SYNC_KEYCLOAK_GROUPS, "FGA_ON_BEHALF_OF": FGA_ON_BEHALF_OF}}


def api_copilot(ctx, m, b):
    """Browser → app → orchestrator agent over mTLS. The human's access token travels with the request."""
    token = session_token(ctx["session"])
    if not token:
        return 401, {"error": "your session expired, sign in again"}
    return mtls_json("POST", f"{ORCHESTRATOR_URL}/chat",
                     {"message": (b.get("message") or "")[:2000], "case_id": b.get("case_id"),
                      "history": (b.get("history") or [])[-10:]},
                     {"Authorization": f"Bearer {token}"}, expect_id=AGENT_PREFIX + "orchestrator", timeout=240)


def api_activity(ctx, m, b):
    return 200, list(ACTIVITY)


ROUTES = [  # method, path, handler, who may call
    ("GET", r"/api/session", api_session, "human"),
    ("GET", r"/api/home", api_home, "human"),
    ("GET", r"/api/activity", api_activity, "human"),
    ("GET", r"/api/admin", api_admin, "human"),
    ("POST", r"/api/copilot", api_copilot, "human"),
    ("GET", r"/api/cases", api_cases, "any"),
    ("GET", r"/api/cases/([\w-]+)", api_case, "any"),
    ("GET", r"/api/cases/([\w-]+)/transactions", api_transactions, "any"),
    ("POST", r"/api/cases/([\w-]+)/documents", api_upload, "any"),
    ("POST", r"/api/cases/([\w-]+)/reimburse", api_reimburse, "any"),
    ("GET", r"/api/documents/([\w-]+)", api_document, "any"),
    ("DELETE", r"/api/documents/([\w-]+)", api_archive, "any"),
    ("POST", r"/api/reports/([\w-]+)/approve", api_approve, "any"),
]


# ---------------------------------------------------------------- HTTP plumbing

class Base(BaseHTTPRequestHandler):
    def send(self, code, obj, ctype="application/json", headers=()):
        data = obj if isinstance(obj, bytes) else json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, url, headers=()):
        self.send_response(302)
        self.send_header("Location", url)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n)) if n else {}
        except ValueError:
            return {}

    def dispatch(self, method, ctx):
        path = urllib.parse.urlparse(self.path).path
        for meth, pattern, fn, who in ROUTES:
            m = re.fullmatch(pattern, path)
            if m and meth == method:
                if who == "human" and not (ctx["user"] and not ctx["agent"]):
                    return self.send(401, {"error": "sign in first"})
                try:
                    return self.send(*fn(ctx, m, self.body()))
                except Denied as d:
                    return self.send(d.status, d.payload)
                except Exception as e:  # never leak a stack trace to the client
                    log("error", path, repr(e))
                    return self.send(500, {"error": str(e)})
        self.send(404, {"error": "not found"})

    def log_message(self, *args):
        pass


class Web(Base):
    """:8000 for people. Identity comes from the Keycloak login session."""

    def session(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        sid = c["nb_session"].value if "nb_session" in c else None
        return sid, SESSIONS.get(sid)

    def route(self, method):
        path = urllib.parse.urlparse(self.path).path
        if method == "GET" and path == "/":
            with open("static/index.html", "rb") as f:
                return self.send(200, f.read(), "text/html; charset=utf-8")
        if method == "GET" and path == "/login":
            state = secrets.token_urlsafe(16)
            PENDING_LOGINS[state] = time.time()
            qs = urllib.parse.urlencode({"client_id": CLIENT_ID, "response_type": "code", "scope": "openid",
                                         "redirect_uri": f"{APP_URL}/callback", "state": state, "prompt": "login"})
            return self.redirect(f"{KC_PUBLIC}/realms/{REALM}/protocol/openid-connect/auth?{qs}")
        if method == "GET" and path == "/callback":
            return self.callback()
        if method == "GET" and path == "/logout":
            sid, s = self.session()
            SESSIONS.pop(sid, None)
            qs = urllib.parse.urlencode({"client_id": CLIENT_ID, "post_logout_redirect_uri": f"{APP_URL}/",
                                         **({"id_token_hint": s["id_token"]} if s and s.get("id_token") else {})})
            return self.redirect(f"{KC_PUBLIC}/realms/{REALM}/protocol/openid-connect/logout?{qs}",
                                 [("Set-Cookie", "nb_session=; Path=/; Max-Age=0")])
        _, s = self.session()
        user = s["user"] if s and session_token(s) else None
        self.dispatch(method, {"user": user, "agent": None, "channel": "browser", "session": s})

    def callback(self):
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
        if PENDING_LOGINS.pop(params.get("state"), None) is None or "code" not in params:
            return self.redirect("/")
        code, tok = http_json("POST", f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/token",
                              {"grant_type": "authorization_code", "code": params["code"],
                               "redirect_uri": f"{APP_URL}/callback", "client_id": CLIENT_ID,
                               "client_secret": CLIENT_SECRET}, form=True)
        info = keycloak_userinfo(tok.get("access_token", "")) if code == 200 else None
        if not info:
            return self.send(502, {"error": "Keycloak login failed", "detail": tok})
        user = user_from_claims(info)
        sync_keycloak_groups(user)
        sid = secrets.token_urlsafe(24)
        SESSIONS[sid] = {"user": user, "access": tok["access_token"], "refresh": tok.get("refresh_token"),
                         "id_token": tok.get("id_token"), "expires": time.time() + tok.get("expires_in", 300)}
        log("[login]", user["id"], "groups", user["groups"], "roles", user["roles"])
        self.redirect("/", [("Set-Cookie", f"nb_session={sid}; Path=/; HttpOnly; SameSite=Lax")])

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_DELETE(self):
        self.route("DELETE")


class AgentAPI(Base):
    """:8443 for AI agents, mutual TLS only. Identity = the SPIFFE ID in the caller's X.509-SVID,
    plus the human it works for when it forwards that person's Keycloak access token."""

    def setup(self):
        self.request.do_handshake()
        super().setup()

    def route(self, method):
        peer = peer_spiffe_id(self.request)
        if not peer or not peer.startswith(AGENT_PREFIX):
            return self.send(403, {"error": f"only AI agents may call this API (caller: {peer})"})
        agent = "agent:" + peer[len(AGENT_PREFIX):]
        user = None
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            info = keycloak_userinfo(auth[7:])
            if not info:
                return self.send(401, {"error": "the user token was rejected by Keycloak"})
            user = user_from_claims(info)
        self.dispatch(method, {"user": user, "agent": agent, "channel": "mTLS", "session": None})

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_DELETE(self):
        self.route("DELETE")


class QuietMTLSServer(MTLSServer):
    def handle_error(self, request, client_address):
        pass  # failed handshakes (e.g. a client without an SVID) are expected; don't print tracebacks


if __name__ == "__main__":
    init_db()
    start_svid_rotation()
    log(f"AUTHZ_MODE={AUTHZ_MODE} store={FGA_STORE_ID or '-'} model={FGA_MODEL_ID or 'latest'} "
        f"sync={FGA_SYNC_KEYCLOAK_GROUPS} on_behalf_of={FGA_ON_BEHALF_OF}")
    threading.Thread(target=QuietMTLSServer(("0.0.0.0", 8443), AgentAPI).serve_forever, daemon=True).start()
    log("Fraud Ops ready: people on http://localhost:8000, AI agents on mTLS :8443")
    ThreadingHTTPServer(("0.0.0.0", 8000), Web).serve_forever()
