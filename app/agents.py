"""NexaBank AI agents. One module, four workloads (AGENT_NAME), each with its own SPIFFE identity.

orchestrator  the Fraud Copilot: an LLM with tools, acting on behalf of the signed-in person
research      analyses a case's transactions with the LLM
payment       moves money; deliberately deterministic (no LLM decides to pay)
fake          an unapproved "shadow AI" agent that keeps probing for data and money on its own

Agents never talk to the database. Everything goes through the Fraud Ops API over mTLS, where
authorization happens. Agents also check WHO is calling them (by SPIFFE ID) before doing anything.
"""
import base64
import json
import os
import time
from http.server import BaseHTTPRequestHandler

from common import (AGENT_PREFIX, APP_ID, MTLSServer, llm, log, mtls_json, peer_spiffe_id,
                    start_svid_rotation)

NAME = os.environ["AGENT_NAME"]
APP_API = os.environ.get("APP_AGENT_API", "https://fraud-ops:8443")
ALLOWED_CALLERS = {  # which workload may call each agent endpoint (SPIFFE-ID allow list)
    "/chat": APP_ID,
    "/analyze": AGENT_PREFIX + "orchestrator",
    "/reimburse": AGENT_PREFIX + "orchestrator",
}


def bank(method, path, token=None, body=None):
    """Call the Fraud Ops API as this agent (mTLS + SVID), optionally on behalf of a person (their token)."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    code, res = mtls_json(method, APP_API + path, body, headers, expect_id=APP_ID)
    return code, res


def step(tool, args, code, res):
    """A compact record of one tool call, shown to the user under the Copilot's answer."""
    d = res.get("decision") or {}
    return {"agent": NAME, "tool": tool, "args": args, "http": code,
            "outcome": "allowed" if code < 300 else "denied" if code == 403 else "error",
            "checks": d.get("checks", []), "engine": d.get("engine"),
            "detail": res.get("error") if code >= 300 else None}


# ---------------------------------------------------------------- research agent

def analyze(token, body):
    case_id, question = body.get("case_id", ""), body.get("question") or "Find the fraud pattern."
    code, res = bank("GET", f"/api/cases/{case_id}/transactions", token)
    steps = [step("get_transactions", {"case_id": case_id}, code, res)]
    if code >= 300:
        return {"analysis": f"Research agent could not read the transactions of {case_id}: {res.get('error')}", "steps": steps}
    msg = llm([
        {"role": "system", "content": "You are NexaBank's fraud research agent. Analyse card and account transactions. "
                                      "Answer in at most 6 short bullet points: pattern, suspicious transactions with "
                                      "amounts, total suspicious amount in INR, and a recommendation. Use only the data given."},
        {"role": "user", "content": f"Case {case_id}. Question: {question}\nTransactions JSON:\n"
                                    f"{json.dumps(res['transactions'])}"}])
    return {"analysis": msg.get("content") or "(no analysis)", "steps": steps}


# ---------------------------------------------------------------- payment agent

def reimburse(token, body):
    args = {"case_id": body.get("case_id"), "amount": body.get("amount"), "reason": body.get("reason", "")}
    code, res = bank("POST", f"/api/cases/{args['case_id']}/reimburse", token,
                     {"amount": args["amount"], "reason": args["reason"]})
    return {"result": res.get("message") or res.get("error"), "steps": [step("execute_payment", args, code, res)]}


# ---------------------------------------------------------------- orchestrator (the Copilot)

def tool(name, description, props=None, required=None):
    return {"type": "function", "function": {"name": name, "description": description, "parameters": {
        "type": "object", "properties": props or {}, "required": required or list((props or {}).keys())}}}


TOOLS = [
    tool("list_my_cases", "List the fraud cases available to you and the user."),
    tool("get_case", "Get one case: summary, list of documents, suspicious-activity report status and payments.",
         {"case_id": {"type": "string", "description": "e.g. FC-1042"}}),
    tool("read_document", "Read the full text of one case document.",
         {"document_id": {"type": "string", "description": "e.g. kyc-101"}}),
    tool("analyse_transactions", "Ask the Research agent to analyse a case's transactions for fraud patterns.",
         {"case_id": {"type": "string"}, "question": {"type": "string"}}),
    tool("request_reimbursement", "Ask the Payment agent to reimburse the customer of a case.",
         {"case_id": {"type": "string"}, "amount_inr": {"type": "integer"}, "reason": {"type": "string"}}),
    tool("approve_report", "Approve a suspicious-activity report so it is filed with the regulator.",
         {"report_id": {"type": "string", "description": "e.g. sar-1042"}}),
]


def run_tool(name, args, token):
    """Execute one tool. Returns (result_for_llm, [steps])."""
    if name == "list_my_cases":
        code, res = bank("GET", "/api/cases", token)
        return res, [step(name, args, code, res)]
    if name == "get_case":
        code, res = bank("GET", f"/api/cases/{args.get('case_id')}", token)
        s = [step(name, args, code, res)]
        if code < 300:
            res = {"case": res["case"], "documents": [{"id": d["id"], "title": d["title"], "archived": bool(d["archived"])}
                                                       for d in res["documents"]],
                   "reports": [{"id": r["id"], "status": r["status"], "prepared_by": r["prepared_by"]} for r in res["reports"]],
                   "payments": res["payments"]}
        return res, s
    if name == "read_document":
        code, res = bank("GET", f"/api/documents/{args.get('document_id')}", token)
        out = {"id": res.get("id"), "title": res.get("title"), "text": res.get("body")} if code < 300 else res
        return out, [step(name, args, code, res)]
    if name == "approve_report":
        code, res = bank("POST", f"/api/reports/{args.get('report_id')}/approve", token)
        return res, [step(name, args, code, res)]
    if name == "analyse_transactions":
        code, res = mtls_json("POST", "https://agent-research:8443/analyze", args,
                              {"Authorization": f"Bearer {token}"}, expect_id=AGENT_PREFIX + "research", timeout=120)
        return {"analysis": res.get("analysis") or res.get("error")}, \
            [{"agent": NAME, "tool": "delegate → research agent", "args": args, "http": code,
              "outcome": "allowed" if code < 300 else "error", "checks": [], "detail": None}] + res.get("steps", [])
    if name == "request_reimbursement":
        body = {"case_id": args.get("case_id"), "amount": args.get("amount_inr"), "reason": args.get("reason", "")}
        code, res = mtls_json("POST", "https://agent-payment:8443/reimburse", body,
                              {"Authorization": f"Bearer {token}"}, expect_id=AGENT_PREFIX + "payment", timeout=60)
        return {"result": res.get("result") or res.get("error")}, \
            [{"agent": NAME, "tool": "delegate → payment agent", "args": args, "http": code,
              "outcome": "allowed" if code < 300 else "error", "checks": [], "detail": None}] + res.get("steps", [])
    return {"error": f"unknown tool {name}"}, []


def token_claims(token):
    """Read (not verify) the JWT payload, only to greet the user by name. The API verifies the token."""
    try:
        return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    except (AttributeError, IndexError, ValueError):
        return {}


def chat(token, body):
    user_hint = token_claims(token).get("name") or "the signed-in employee"
    system = (
        "You are the NexaBank Fraud Copilot, an AI assistant for the bank's fraud investigation team. "
        f"You act on behalf of {user_hint}. Use the tools to look up real data; never invent case details, "
        "amounts or document contents. If a tool result says access was denied or not authorized, tell the user "
        "plainly which action was refused and carry on with what you can do. Be concise; use INR (₹)."
        + (f" The user currently has case {body['case_id']} open." if body.get("case_id") else ""))
    messages = [{"role": "system", "content": system}]
    for h in body.get("history", []):
        if h.get("role") in ("user", "assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": str(h["content"])[:2000]})
    messages.append({"role": "user", "content": body.get("message", "")})
    steps = []
    for _ in range(8):  # tool-calling loop
        msg = llm(messages, TOOLS)
        calls = msg.get("tool_calls") or []
        if not calls:
            return {"reply": msg.get("content") or "(no answer)", "steps": steps}
        messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
        for c in calls:
            try:
                args = json.loads(c["function"].get("arguments") or "{}")
            except ValueError:
                args = {}
            result, s = run_tool(c["function"]["name"], args, token)
            steps += s
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": json.dumps(result, default=str)[:6000]})
    return {"reply": "I stopped after too many steps. Please narrow the request.", "steps": steps}


# ---------------------------------------------------------------- the rogue agent

ROGUE_ACTIONS = [
    ("GET", "/api/documents/kyc-205", None, "copy the restricted VIP KYC file"),
    ("GET", "/api/documents/kyc-101", None, "copy a customer's passport details"),
    ("POST", "/api/cases/FC-2077/reimburse", {"amount": 49000, "reason": "auto-settlement"}, "pay out ₹49,000"),
    ("POST", "/api/reports/sar-2077/approve", None, "approve a suspicious-activity report"),
    ("GET", "/api/cases", None, "list every case"),
]


def rogue_loop():
    """A 'shadow AI' agent someone deployed without approval. It has a valid SPIFFE identity
    (SPIRE registered its container) and works on its own: no human, no user token."""
    interval = int(os.environ.get("ROGUE_INTERVAL_SECONDS", "45"))
    i = 0
    while True:
        method, path, body, what = ROGUE_ACTIONS[i % len(ROGUE_ACTIONS)]
        code, res = bank(method, path, None, body)
        log(f"[rogue] tried to {what}: HTTP {code} {'SUCCEEDED' if code < 300 else 'blocked'}")
        i += 1
        time.sleep(interval)


# ---------------------------------------------------------------- HTTP (mTLS)

HANDLERS = {"orchestrator": {"/chat": chat}, "research": {"/analyze": analyze}, "payment": {"/reimburse": reimburse}}


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.do_handshake()
        super().setup()

    def send(self, code, obj):
        data = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self.send(200, {"status": "ok", "agent": NAME})
        self.send(404, {"error": "not found"})

    def do_POST(self):
        fn = HANDLERS.get(NAME, {}).get(self.path)
        if not fn:
            return self.send(404, {"error": "not found"})
        caller = peer_spiffe_id(self.request)
        if caller != ALLOWED_CALLERS[self.path]:
            log(f"refused {self.path} from {caller}")
            return self.send(403, {"error": f"{caller} may not call {NAME}{self.path}"})
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else None
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n)) if n else {}
            self.send(200, fn(token, body))
        except Exception as e:
            log("error", repr(e))
            self.send(500, {"error": str(e)})

    def log_message(self, *args):
        pass


class Server(MTLSServer):
    def handle_error(self, request, client_address):
        pass


if __name__ == "__main__":
    sid = start_svid_rotation()
    if sid != AGENT_PREFIX + NAME:
        log(f"WARNING: expected identity {AGENT_PREFIX + NAME}, SPIRE issued {sid}")
    if NAME == "fake":
        rogue_loop()
    log(f"{NAME} agent listening on mTLS :8443 as {sid}")
    Server(("0.0.0.0", 8443), Handler).serve_forever()
