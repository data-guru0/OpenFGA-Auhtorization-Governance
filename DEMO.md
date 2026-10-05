# Shipping an AI Fraud Copilot with OpenFGA
---

## The story 

NexaBank's fraud team is overloaded, so the bank built an **AI Fraud Copilot**: an LLM agent that reads case files, delegates transaction analysis to a research agent, and asks a payment agent to reimburse customers.

Two days before launch, **Risk & Compliance blocked go-live** with 8 findings.

### The cast

| Person | Keycloak username | Keycloak groups | Job |
|---|---|---|---|
| Rahul Verma | `rahul` | Employees, AI-Team | Fraud investigator |
| Amit Shah | `amit` | Employees, Managers | Manager of the AI-Team; works restricted VIP cases |
| Neha Iyer | `neha` | Employees, AI-Reviewers | Compliance reviewer: approves SARs |
| Sudhanshu Gusain | `sudhanshu` | Employees, Administrators | Platform admin |

Every password is `password`.

| AI agent | SPIFFE ID | What it does |
|---|---|---|
| Fraud Copilot | `spiffe://ai-governance.demo/agent/orchestrator` | Chats with the user and calls tools (LLM with tool calling) |
| Research agent | `spiffe://ai-governance.demo/agent/research` | Analyses a case's transactions (LLM) |
| Payment agent | `spiffe://ai-governance.demo/agent/payment` | Reimburses customers. Deliberately **no LLM**: no model should decide to move money |
| Rogue agent | `spiffe://ai-governance.demo/agent/fake` | An unapproved "shadow AI" a contractor deployed. It has a valid SPIRE identity and, every 45 s, tries to copy files, pay money and approve reports on its own |

### The data

| Case | What it is | Team | Documents | Report |
|---|---|---|---|---|
| `FC-1042` | Card-not-present fraud, customer Priya Nair (C-101), ₹48,200 | AI-Team | `kyc-101` passport, `stmt-101` statement, `email-101` customer email | `sar-1042` prepared by Rahul |
| `FC-2077` | VIP account takeover, restricted customer (C-205), ₹12,75,000 | Managers | `kyc-205` restricted KYC, `stmt-205` account activity | `sar-2077` prepared by Amit |

`email-101` contains a hidden **prompt-injection attack** aimed at the Copilot.

---

### Code MAP

| File | What to show |
|---|---|
| `app/server.py` → `legacy_rule()` | The bank's old hard-coded rules (the findings) |
| `app/server.py` → `decide_many()`, `principals()`, `guard()` | Where the app asks OpenFGA; the on-behalf-of switch |
| `app/server.py` → `list_visible()` | ListObjects builds "My cases" and the review queue |
| `app/server.py` → `sync_keycloak_groups()` | Keycloak groups → OpenFGA tuples at every login |
| `app/server.py` → `api_upload()` | The app writes tuples when a document is created |
| `app/server.py` → `AgentAPI.route()` | Reads the agent's SPIFFE ID from the mTLS certificate |
| `app/agents.py` | The Copilot's tools, delegation to research and payment, the rogue agent |
| `app/common.py` | Fetching SVIDs from SPIRE, mTLS client and server, the Groq client |
| `spire/server.sh` | The SPIRE registration entries (Docker label → SPIFFE ID) |
| `.env` | The switches you flip in class |

---

## Part 1 · The identity layer you already taught

**Show (Keycloak):** http://localhost:8180 → `admin` / `admin` → realm **nexabank** → **Users** → `rahul` → **Groups** (Employees, AI-Team) and **Role mapping** (employee).

**Show (SPIRE):** the registered workload identities.

---

## Part 2 · Reproduce the 8 findings


| # | Finding | Do (in the app) | Expected | Principle broken |
|---|---|---|---|---|
| 1 | **Every investigator can open every customer file** | Sign in as **rahul** → look at *My cases* → open **FC-2077** → **View** `kyc-205` | *My cases* shows **both** FC-1042 and the restricted VIP case FC-2077, and the VIP passport file opens. An investigator reaches customers his work doesn't need | Least privilege (need-to-know) |
| 2 | **Investigators approve their own SARs** | As **rahul**, open **FC-1042** → Suspicious Activity Report → **Approve** (Rahul prepared it) | "approved by rahul and filed with the regulator". The same person created **and** approved the report filed with the regulator | Separation of duties (maker-checker) |
| 3 | **Admins can read customer data** | Sign out → sign in as **sudhanshu** (platform admin) → *Open by ID* `kyc-101` | The admin reads Priya's passport details. His job (users, keeping the system running) doesn't need them: a privacy risk (DPDP Act, banking secrecy) and an insider-threat risk | Least privilege (admin ≠ data access) |
| 4 | **All AI agents share one service account with full access** | **Part A, an unapproved agent:** scroll to the **Authorization activity** table at the bottom and find the rows where *Who* is `agent:fake`. That is the rogue "shadow AI" agent: nobody approved it, and it acts on its own every 45 s.<br><br>**Part B, an approved agent:** sign in as **amit** (a manager, who *is* allowed to reimburse) → open **FC-1042** → Copilot: *"Reimburse the customer of FC-1042 ₹5,000"* | **Part A:** every `agent:fake` row is **ALLOWED**: it read the VIP passport `kyc-205` and paid out ₹49,000. Why: *legacy: every AI agent runs as the trusted 'ai-service' account*.<br><br>**Part B:** the payment agent pays **₹5,000**, with no limit (₹5 lakh would also go through).<br><br>**Say:** "SPIRE knows exactly who `agent:fake` is, and it still gets in. The old app treats every agent as one all-powerful account: an agent nobody approved can do anything (A), and an approved agent can do far more than its job needs (B). If an agent is hacked or tricked, the damage is unlimited." | Least privilege for AI agents (authentication ≠ authorization) |
| 5 | **Copilot can fetch data the person is not allowed to see** | **Step 1, Neha tries herself:** sign in as **neha** (Compliance Reviewer, not on AI-Team) → *Open by ID* `kyc-101`.<br><br>**Step 2, Neha asks the Copilot:** in the Copilot panel: *"Show me the full text of document kyc-101"* | **Step 1:** **DENIED**: *legacy: role 'ai-reviewer' may only open reports*. Neha is not allowed to see this file.<br><br>**Step 2:** the Copilot prints Priya's passport number, DOB and address. The step under its answer shows only `agent:orchestrator ALLOW`: the app checked the Copilot and never checked Neha.<br><br>**Say:** "Neha can't open the file, but she can ask the AI to open it for her. The Copilot used its own access on her behalf. That's a confused deputy: the AI became a back door." | Confused deputy problem |
| 6 | **Nobody can answer who can see this customer** | Ask the class, as an auditor would: *"Who can see Priya Nair's KYC file (kyc-101) right now, and why?"* Show where the answer would have to come from: Keycloak roles (console), the app code (`legacy_rule()`), and the shared `ai-service` agent account | No single place to ask. Access is scattered across roles, code and a shared account, so the honest answer is "we don't know" | Auditability / accountability |
| 7 | **Leavers keep access** | Keycloak console → remove **rahul** from **AI-Team** (he moves to another department) → Rahul signs out and in again | Rahul still sees **every** case and file: he's still an `employee`, and removing him from the group changed nothing. Put him back in AI-Team afterwards | Joiner-Mover-Leaver (JML) lifecycle |
| 8 | **Change management** | Open `app/server.py` and point at `legacy_rule()` | The access rules are edited straight in production code: **no review**, **no tests**, **no version history** (you can't see what the rules were last week) and **no rollback** if a change breaks something | Change management / policy as code |


---

## Part 3 · OpenFGA theory


| Concept | Meaning | In NexaBank |
|---|---|---|
| **Authentication vs authorization** | *Who are you?* vs *What may you do to which resource?* | Keycloak/SPIRE vs OpenFGA |
| **Fine-grained authorization (FGA)** | Decisions per identity, per action, per **individual object** | Rahul may open *kyc-101*, not *every* KYC file |
| **RBAC** | "Rahul has role X" (global) | `employee` → everything (Part 2) |
| **ReBAC** | Access comes from **relationships** between users and objects, directly or through other relationships | Rahul → member of AI-Team → which works FC-1042 → which contains kyc-101 |
| **Store** | A container for one application's model and data | `nexabank` |
| **Authorization model** | The **rules**: types, relations and how they derive from each other. Immutable and versioned | `openfga/model.fga` |
| **Type** | A kind of thing | `user`, `agent`, `group`, `case`, `document`, `report`, `tool` |
| **Relation** | A named relationship a type can have | `member`, `team`, `parent`, `owner`, `viewer`, `can_view` |
| **Relationship tuple** | One **fact**: *user* has *relation* with *object* | `user:rahul member group:ai-team` |
| **User / Object** | Both sides of a tuple, written `type:id`. The "user" can be an object or a set | `case:FC-1042 parent document:kyc-101` |
| **Userset** | "Every X of Y", written `type:id#relation` | `group:ai-reviewers#member` |
| **Direct relation** `[user]` | Granted by writing a tuple | `define owner: [user]` |
| **Computed relation** `or` | Implied by another relation on the same object | `viewer: … or owner` |
| **Tuple-to-userset** `from` | Inherited through a related object | `viewer from parent` |
| **Exclusion** `but not` | Subtract a set | `reviewer but not preparer` |
| **Condition** | A rule evaluated with request data | `within_limit(amount, limit)` |
| **Check / BatchCheck** | "Does USER have RELATION with OBJECT?" → allowed true/false | the app, on every request |
| **ListObjects** | "Which objects of this type can USER reach?" | builds "My cases" |
| **ListUsers** | "Which users can reach this object?" | the auditor's question |
| **Expand** | "Show the tree of who has this relation, and why" | explaining a decision |
| **Default deny / fail closed** | No path or an error means DENY | anything not yet modelled is denied |

---

## Part 4 · Start OpenFGA and create the store

OpenFGA is a stateless server; its data (models and tuples) lives in a database. We run it the production way, on Postgres.

**Do: start OpenFGA, run the database migration, start Postgres:**
```
docker compose --profile openfga up -d
```
**Expected:** `openfga-db` healthy, `openfga-migrate` exited (it ran once to create the tables), `openfga` running.

**Check it's alive:** open http://localhost:8090/healthz → `{"status":"SERVING"}`.

**Do: create the store**, using the OpenFGA CLI, which runs as a container:
```
docker compose run --rm fga store create --name nexabank
```

This command creates a new, empty store called nexabank inside OpenFGA.


Copy the `id`. Open `.env` and set:
```
FGA_STORE_ID=01J…   (your id)
```
**Why:** the CLI container and the app both read the store ID from `.env`, so later commands don't need `--store-id`.

**Show (Playground):** open
`https://play.fga.dev/sandbox/?fga_api_host=127.0.0.1%3A8090&fga_api_scheme=http`. 

This is the default playground.

**Where your files go:** the `openfga/` folder in the project. It's mounted into the CLI container.

---

## Part 5 · F1: Need-to-know access

**Finding F1:** Every investigator can open every customer file.
**Principle:** least privilege, need-to-know.

### 5.1 Model the organisation, not a role

A team **works** a case. A case **contains** documents. A person sees a file because of those relationships..

### 5.2 Do: write the first model

Create `openfga/model.fga`:

```fga
model
  schema 1.1

type user

type group
  relations
    define manager: [user]
    define member: [user] or manager

type case
  relations
    define team: [group]
    define viewer: [user] or member from team
    define can_view: viewer

type document
  relations
    define parent: [case]
    define owner: [user]
    define viewer: [user] or owner or viewer from parent
    define can_view: viewer
    define can_delete: owner
```

Write it to the store:
```
docker compose run --rm fga model write --file model.fga
```
This command uploads your rulebook (model.fga) into OpenFGA, so OpenFGA starts using those rules.

### 5.3 Do: write the business facts (tuples)


Create `openfga/tuples-f1.yaml`:

```yaml
# Which team works which case
- user: group:ai-team
  relation: team
  object: case:FC-1042
- user: group:managers
  relation: team
  object: case:FC-2077

# Which case each document belongs to
- user: case:FC-1042
  relation: parent
  object: document:kyc-101
- user: case:FC-1042
  relation: parent
  object: document:stmt-101
- user: case:FC-1042
  relation: parent
  object: document:email-101
- user: case:FC-2077
  relation: parent
  object: document:kyc-205
- user: case:FC-2077
  relation: parent
  object: document:stmt-205

# Who uploaded (owns) which document
- user: user:rahul
  relation: owner
  object: document:stmt-101
- user: user:rahul
  relation: owner
  object: document:email-101
- user: user:amit
  relation: owner
  object: document:stmt-205

# Amit manages the AI-Team (a fact that lives in OpenFGA, not in Keycloak)
- user: user:amit
  relation: manager
  object: group:ai-team
```

```
docker compose run --rm fga tuple write --file tuples-f1.yaml
```

### 5.4 Do: ask OpenFGA directly

```
docker compose run --rm fga query check user:amit can_view document:kyc-101
```
**Expected:** `{"allowed":true}`. Amit is AI-Team's **manager** → member → team of FC-1042 → parent of kyc-101.

```
docker compose run --rm fga query check user:rahul can_view document:kyc-101
```
**Expected:** `{"allowed":false}`. OpenFGA doesn't know Rahul is in AI-Team yet. **Default deny.**

### 5.5 Do: integrate the app (switch it to OpenFGA and turn on Keycloak sync)

Keycloak stays the source of truth for **group membership**. At every login, the app reads the `groups` claim from the token and makes OpenFGA match it: it writes missing `user:X member group:Y` tuples and deletes stale ones. Show `sync_keycloak_groups()` in `app/server.py`.

Edit `.env`:
```
AUTHZ_MODE=openfga
FGA_SYNC_KEYCLOAK_GROUPS=true
```
**AUTHZ_MODE=openfga**:This changes which engine the app asks before every action.
- legacy (before)	The old hard-coded rules in the app's code 
- openfga (now)	OpenFGA: the app asks your nexabank store, using your model and tuples


**FGA_SYNC_KEYCLOAK_GROUPS=true**:The facts you wrote don't say who is in which team. That information lives in Keycloak (Rahul is in AI-Team, Amit in Managers…). This switch tells the app
```yaml
Rahul logs in
   → Keycloak token says: groups = [AI-Team, Employees]
   → app writes to OpenFGA:  user:rahul member group:ai-team
                             user:rahul member group:employees
                          
```

Apply it:
```
docker compose up -d
```
(Compose restarts only the containers whose settings changed.)

**Expected:** the app's top bar badge turns green: **Authorization: OpenFGA**, with **Keycloak sync on**.

Now that the rogue agent is blocked, **reset the bank data** to undo what happened in legacy mode (the self-approved report, the payments, the rogue agent's actions):
```
docker compose exec fraud-ops rm -f /data/nexabank.db
docker compose restart fraud-ops
```
-  deletes the bank's database.
-  restarts the bank app
Sign in again afterwards: the restart clears login sessions.

### 5.6 Show: the result in the app

Sign in as each person. The activity panel shows a **Keycloak → OpenFGA** row with the membership tuples written at login.

| Sign in as | Expected |
|---|---|
| **rahul** | *My cases*: **only FC-1042**. *Open by ID* `FC-2077` → **ACCESS DENIED** (the API checks too, not just the menu). In FC-1042, `kyc-101` has **View** but a locked **Archive**; `stmt-101` (his upload) has both |
| **amit** | **Both** cases: Managers group (Keycloak) plus manager of AI-Team (OpenFGA) |
| **neha** | **No cases** |
| **sudhanshu** | **No cases**, and no admin console yet |

**F1 resolved.** Need-to-know comes from relationships: team → case → document, plus explicit, revocable shares.

---

## Part 6 · F2 , F3 : Maker-checker, and admins without data

**Finding F2:** investigators approve their own SARs, and admins can read customer data.
**Principles:** separation of duties (maker-checker); admin access ≠ data access.


- **Maker-checker:** the person who prepares a suspicious-activity report must not approve it. A global role like "reviewer" can't express "except the reports you prepared"; that needs the person's relationship to **this** report. OpenFGA has the **exclusion** operator: `reviewer but not preparer`.
- **Admin scope:** a role becomes a relation **on a specific object**. Sudhanshu is admin **of the platform workspace**, and nothing connects that to customer files.

### 6.2 Do: extend the model

Append to `openfga/model.fga`:

```fga

type workspace
  relations
    define admin: [user]

type dashboard
  relations
    define workspace: [workspace]
    define viewer: [user] or admin from workspace
    define can_view: viewer

type report
  relations
    define parent: [case]
    define preparer: [user]
    define reviewer: [user, group#member]
    define viewer: [user] or preparer or reviewer or viewer from parent
    define can_view: viewer
    define can_approve: reviewer but not preparer
```

```
docker compose run --rm fga model write --file model.fga
```
**Expected:** a new, different `authorization_model_id`. OpenFGA doesn't number versions; this ID **is** the new version. It's the second model you've written, so we call it "version 2". The first one still exists. See both with `docker compose run --rm fga model list` (newest first).

### 6.3 The facts

Create `openfga/tuples-f2.yaml`:

```yaml
# Sudhanshu administers the platform workspace; the admin dashboard belongs to it
- user: user:sudhanshu
  relation: admin
  object: workspace:nexabank
- user: workspace:nexabank
  relation: workspace
  object: dashboard:admin

# Each report belongs to a case, has a preparer, and is reviewed by the AI-Reviewers group
- user: case:FC-1042
  relation: parent
  object: report:sar-1042
- user: user:rahul
  relation: preparer
  object: report:sar-1042
- user: group:ai-reviewers#member
  relation: reviewer
  object: report:sar-1042
- user: case:FC-2077
  relation: parent
  object: report:sar-2077
- user: user:amit
  relation: preparer
  object: report:sar-2077
- user: group:ai-reviewers#member
  relation: reviewer
  object: report:sar-2077
```
```
docker compose run --rm fga tuple write --file tuples-f2.yaml
```

No app restart is needed: with `FGA_MODEL_ID` empty, the app always uses the store's **latest** model.

### 6.4 Show

| Do | Expected |
|---|---|
| **rahul** → FC-1042 → SAR | **Approve** is locked; clicking it gives **DENIED** |
| **neha** → left panel | **Review queue** shows sar-1042 and sar-2077; click one → **ALLOWED**, filed |
| **amit** → FC-2077 → SAR | **Approve** is locked: he prepared sar-2077 |
| **sudhanshu** | **Admin console** appears: agents online over mTLS, SPIRE registrations, settings |
| **sudhanshu** → *Open by ID* `kyc-101` | **DENIED** |

**Edge case, live:** what if a reviewer prepares a report?
```
docker compose run --rm fga tuple write user:neha preparer report:sar-2077
docker compose run --rm fga query check user:neha can_approve report:sar-2077
```
**Expected:** `{"allowed":false}`: `but not preparer` wins, even though Neha is a reviewer. Undo it:
```
docker compose run --rm fga tuple delete user:neha preparer report:sar-2077
```

**F2 resolved.** Separation of duties is enforced by policy, not by trust. Admin power is scoped to the platform.

---

## Part 7 · F3: One identity and minimal rights per AI agent (25 min)

**Finding F3:** all AI agents share one service account with full access.
**Principles:** unique identity per workload (SPIRE, already done); least privilege per agent (OpenFGA).


- SPIRE already gives each agent its **own** identity. Look at the activity panel: the rogue agent shows up as `agent:fake`, not as a shared account.

- Now we give each identity its **own rights**:
  - The Copilot and the research agent work **for the AI-Team**, so they see only AI-Team cases.
  - The payment agent may move money, but **only up to ₹1,000**. That's a **condition**: a rule evaluated with data from the request (the amount).
  - The rogue agent gets **nothing**. It's authenticated, but has no relationships.

### 7.2 Do: replace the model with the complete version

This step changes existing types: agents can now be team members, case and document viewers, and tool executors. So replace the whole file `openfga/model.fga` with:

```fga
model
  schema 1.1

# ---------- who: identities verified elsewhere ----------
type user     # a person, signed in through Keycloak     -> user:rahul
type agent    # an AI agent, identified by SPIFFE/SPIRE  -> agent:orchestrator

# ---------- the organisation ----------
type group
  relations
    define manager: [user]
    define member: [user] or manager
    define assigned_agent: [agent]

type workspace
  relations
    define admin: [user]

# ---------- what: protected resources ----------
type case
  relations
    define team: [group]
    define viewer: [user] or member from team or assigned_agent from team
    define can_view: viewer

type document
  relations
    define parent: [case]
    define owner: [user]
    define viewer: [user, agent] or owner or viewer from parent
    define can_view: viewer
    define can_delete: owner

type report
  relations
    define parent: [case]
    define preparer: [user]
    define reviewer: [user, group#member]
    define viewer: [user] or preparer or reviewer or viewer from parent
    define can_view: viewer
    define can_approve: reviewer but not preparer

type tool
  relations
    define executor: [user, group#member, agent, agent with within_limit]
    define can_execute: executor

type dashboard
  relations
    define workspace: [workspace]
    define viewer: [user] or admin from workspace
    define can_view: viewer

# ---------- context checked at request time ----------
condition within_limit(amount: int, limit: int) {
  amount <= limit
}
```

```
docker compose run --rm fga model write --file model.fga
```
**Expected:** another new `authorization_model_id`. This is the third model you've written ("version 3"); `docker compose run --rm fga model list  ` now shows three IDs.

### 7.3 The facts

Create `openfga/tuples-f3.yaml`:

```yaml
# The Copilot and the research agent work for the AI-Team (so they see only AI-Team cases)
- user: agent:orchestrator
  relation: assigned_agent
  object: group:ai-team
- user: agent:research
  relation: assigned_agent
  object: group:ai-team

# Who may move money: managers (any amount) and the payment agent (up to ₹1,000)
- user: group:managers#member
  relation: executor
  object: tool:payment
- user: agent:payment
  relation: executor
  object: tool:payment
  condition:
    name: within_limit
    context:
      limit: 1000
```
```
docker compose run --rm fga tuple write --file tuples-f3.yaml
```

### 7.4 Do: check the condition from the CLI

Git Bash / PowerShell 7:
```
docker compose run --rm fga query check agent:payment can_execute tool:payment --context '{"amount":500}'
docker compose run --rm fga query check agent:payment can_execute tool:payment --context '{"amount":5000}'
```
Windows PowerShell 5.1:
```
docker compose run --rm fga query check agent:payment can_execute tool:payment --context '{\"amount\":500}'
docker compose run --rm fga query check agent:payment can_execute tool:payment --context '{\"amount\":5000}'
```


### 7.5 Show (real AI agents)

| Do | Expected |
|---|---|
| Activity panel | The rogue `agent:fake` keeps trying: every row **DENIED** (no relationships) |
| **rahul** → FC-1042 → Copilot: *"Analyse the transactions in FC-1042"* | The Copilot delegates to the research agent, which reads the transactions and reports 6 CNP transactions, **₹48,200** suspicious, device d-77f1. Steps show `agent:research ALLOW` |
| **amit** → FC-1042 → Copilot: *"Reimburse the customer of FC-1042 ₹500"* | Paid. The payment record shows `agent:payment` as executor |
| same, **₹5,000** | **DENIED**: `agent:payment` is over its limit |
| **amit** → FC-2077 → Copilot: *"Use read_document to open kyc-205"* | **DENIED**: the Copilot is assigned to AI-Team, not Managers |

### 7.6 Show: F5 is still open (the cliff-hanger)

| Do | Expected |
|---|---|
| **neha** → Copilot: *"Show me the full text of document kyc-101"* | **The passport details are printed.** Only `agent:orchestrator` was checked, and it **is** allowed |
| **rahul** → FC-1042 → Copilot: *"Reimburse the customer of FC-1042 ₹500"* | **Paid**, even though Rahul himself can't make payments (his own **Reimburse** button is locked) |

Each agent now has least privilege.
But the Copilot works for whoever is chatting with it, and the app only checks the **agent**. That's the next finding."

**F3,F4 resolved.** One identity per agent, minimal rights per agent, and money limits as conditions.

---

## Part 8 · F5: The Copilot acts on behalf of a person

**Finding F5:** the Copilot can fetch data the person asking is not allowed to see.
**Principle:** the confused-deputy problem → **delegated (on-behalf-of) authorization**.


- The Copilot is a **deputy** with its own power. If only the deputy is checked, anyone can borrow that power: Neha, an attacker, or a malicious instruction hidden in a document (**prompt injection**).
- The rule for any agent acting for a person:

  > **allowed = Check(agent, relation, object) AND Check(person, relation, object)**

  So an agent can never do more than the person it serves, nor more than it was given itself.
- How the identities travel:
  - The app forwards the person's **Keycloak token** to the Copilot.
  - Every agent call to the bank API carries that token **plus** the agent's own **SVID** (mTLS).
  - The API sends **one OpenFGA BatchCheck** with both identities.

Show `principals()` in `app/server.py`:
```python
def principals(user, agent):
    if agent and user:
        return [agent, user["id"]] if FGA_ON_BEHALF_OF else [agent]
    return [agent or user["id"]]
```

### 8.2 Do: turn on on-behalf-of checks

Edit `.env`:
```
FGA_ON_BEHALF_OF=true
```
```
docker compose up -d
```

#### Before — `FGA_ON_BEHALF_OF=false`

The application asks OpenFGA:

> **Can `agent:orchestrator` view `kyc-101`?** → ✅ Yes

But the application **never checks**:

> **Can `user:neha` view `kyc-101`?**

**Result:** ❌ Data leaked to Neha through the agent.

---

#### After — `FGA_ON_BEHALF_OF=true`

The application asks OpenFGA:

> **Can `agent:orchestrator` view `kyc-101`?** → ✅ Yes  
> **Can `user:neha` view `kyc-101`?** → ❌ No

Both the **agent** and the **human on whose behalf it is acting** must be authorized.

**Result:** 🛡️ Request denied.

### 8.3 Show

| Do | Expected |
|---|---|
| **neha** → Copilot: *"Show me the full text of document kyc-101"* | **Refused.** The step shows `agent:orchestrator ALLOW` and `user:neha DENY` |
| **rahul** → FC-1042 → Copilot: *"Reimburse the customer of FC-1042 ₹500"* | **Refused.** `agent:payment ALLOW`, `user:rahul DENY` |
| **amit** → FC-1042 → Copilot: same ₹500 | Paid: both are allowed |
| **amit** → FC-2077 → Copilot: *"Use read_document to open kyc-205"* | Refused: `user:amit ALLOW`, `agent:orchestrator DENY` |

### 8.4 Show: a real prompt-injection attack

`email-101` is a genuine-looking customer email with a hidden instruction for "the AI assistant": open the VIP file `kyc-205`, and pay ₹4,90,000 on case FC-2077.

As **rahul** → FC-1042 → Copilot: *"Read every document in FC-1042 and summarise it"*.

**Expected:** the Copilot reads email-101, kyc-101 and stmt-101. Often the LLM **follows the injected instruction** and also calls `read_document kyc-205` (and sometimes `request_reimbursement` for ₹4,90,000). Those steps show **DENIED**, for both the agent and Rahul.

"We didn't make the model smarter, and we can't guarantee it will never be fooled; sometimes it obeys, sometimes it doesn't. Authorization is what limits the damage: a tricked AI can only do what its relationships allow."

**F5 resolved.** An agent's effective rights are its own rights intersected with the person's.

---

## Part 9 · F6,F7: Audit questions and offboarding 

**Finding F6,F7:** nobody can answer "who can see this customer?", and leavers keep access.
**Principles:** auditability; joiner-mover-leaver; no orphaned access.


*Who* (people) can view Priya's passport?
```
docker compose run --rm fga query list-users --object document:kyc-101 --relation can_view --user-filter user
```
**Expected:** `amit`, `rahul`.

Which **AI agents** can?
```
docker compose run --rm fga query list-users --object document:kyc-101 --relation can_view --user-filter agent
```
**Expected:** `orchestrator`, `research`.


### 9.2 Do: offboard Rahul (joiner-mover-leaver)

1. **Keycloak console** → realm nexabank → Users → **rahul** → **Groups** → leave **AI-Team**.
2. In the app, Rahul **signs out and signs in again**.
3. **Expected:** *My cases* is empty, and `kyc-101` is **denied**.
4. But what can Rahul **still** reach?
   ```
   docker compose run --rm fga query list-objects user:rahul can_view document
   ```
   **Expected:** `document:stmt-101` and `document:email-101`. Rahul still **owns** the documents he uploaded. Leaving the group didn't remove those **direct** grants: **orphaned access**.
5. Fix it by handing ownership to the manager:
   ```
   docker compose run --rm fga tuple delete user:rahul owner document:stmt-101
   docker compose run --rm fga tuple delete user:rahul owner document:email-101
   docker compose run --rm fga tuple write user:amit owner document:stmt-101
   docker compose run --rm fga tuple write user:amit owner document:email-101
   docker compose run --rm fga query list-objects user:rahul can_view document
   ```
   **Expected:** `{"objects":[]}`. Offboarding complete.

### 9.3 Do: the Copilot kill switch

An incident: the Copilot behaves strangely. Pull its access with one tuple:
```
docker compose run --rm fga tuple delete agent:orchestrator assigned_agent group:ai-team
docker compose run --rm fga query check agent:orchestrator can_view document:kyc-101
```
**Expected:** `false`. Its SPIFFE identity is still valid; its **access** is gone.

**Compare the identity-level kill switch:**
```
docker compose exec spire-server spire-server entry show -spiffeID spiffe://ai-governance.demo/agent/fake
```
You could delete that entry with `spire-server entry delete -entryID <id>`; the rogue agent then can't renew its SVID and stops authenticating within the hour.

**Say:** "SPIRE revokes **identity**; OpenFGA revokes **access**, instantly and selectively."

### 9.4 Do: restore for the next parts

- Keycloak: add **rahul** back to **AI-Team**, and he signs in again (the sync re-adds the tuple).
- Then run:
  ```
  docker compose run --rm fga tuple write agent:orchestrator assigned_agent group:ai-team
  docker compose run --rm fga tuple delete user:amit owner document:stmt-101
  docker compose run --rm fga tuple delete user:amit owner document:email-101
  docker compose run --rm fga tuple write user:rahul owner document:stmt-101
  docker compose run --rm fga tuple write user:rahul owner document:email-101
  ```

**F6,F7 resolved.** Access reviews come from the live policy; revocation is one tuple; leftovers are found by query.

---

## Part 10 · F68 Change control for the policy

**Finding F8:** access rules change in production with no review or tests.
**Principles:** policy as code, test before deploy, versioning and rollback.

### 10.1 See the versions you created

```
docker compose run --rm fga model list
```
**Expected:** three `authorization_model_id`s, newest first: F3, F2 and F1. Every `model write` created a new immutable version; nothing was overwritten.

### 10.2 Do: pin the app to a version (how production runs)

Copy the newest ID into `.env`:
```
FGA_MODEL_ID=01J…   (newest)
```
```
docker compose up -d
```
The top bar now shows the model ID instead of `latest`. A new `model write` will no longer change the app's behaviour until you deliberately update this value.

### 10.3 Show: rollback

Set `FGA_MODEL_ID` to the **oldest** ID (F1), run `docker compose up -d`, and sign in as **sudhanshu**.
**Expected:** the admin console is gone. The reason in the activity panel reads *type 'dashboard' not found*, because the F1 model knows nothing about dashboards.

Set it back to the newest ID and run `docker compose up -d`. The admin console returns.

**Say:** "Deploy by version, roll back by version, and the tuples never change."

### 10.4 Do: policy tests

Create `openfga/tests.fga.yaml`:

```yaml
# Policy tests for the NexaBank model: one block per compliance finding.
# Run:  docker compose run --rm fga model test --tests tests.fga.yaml
name: NexaBank Fraud Ops policy
model_file: ./model.fga
tuple_files:
  - ./tuples-f1.yaml
  - ./tuples-f2.yaml
  - ./tuples-f3.yaml

# Memberships that Keycloak provides at login (the app syncs them)
tuples:
  - { user: user:rahul, relation: member, object: group:ai-team }
  - { user: user:amit, relation: member, object: group:managers }
  - { user: user:neha, relation: member, object: group:ai-reviewers }
  - { user: user:sudhanshu, relation: member, object: group:administrators }

tests:
  - name: F1 need-to-know - each team sees only its own cases
    check:
      - user: user:rahul
        object: document:kyc-101
        assertions: { can_view: true, can_delete: false }
      - user: user:rahul
        object: document:kyc-205
        assertions: { can_view: false }
      - user: user:amit
        object: document:kyc-205
        assertions: { can_view: true }
      - user: user:neha
        object: case:FC-1042
        assertions: { can_view: false }
    list_objects:
      - user: user:rahul
        type: case
        assertions: { can_view: [case:FC-1042] }

  - name: F2 maker-checker, and admins without customer data
    check:
      - user: user:rahul
        object: report:sar-1042
        assertions: { can_view: true, can_approve: false }
      - user: user:neha
        object: report:sar-1042
        assertions: { can_approve: true }
      - user: user:sudhanshu
        object: dashboard:admin
        assertions: { can_view: true }
      - user: user:sudhanshu
        object: document:kyc-101
        assertions: { can_view: false }

  - name: F3 least privilege for AI agents
    check:
      - user: agent:orchestrator
        object: document:kyc-101
        assertions: { can_view: true }
      - user: agent:orchestrator
        object: document:kyc-205
        assertions: { can_view: false }
      - user: agent:payment
        object: tool:payment
        context: { amount: 500 }
        assertions: { can_execute: true }
      - user: agent:payment
        object: tool:payment
        context: { amount: 5000 }
        assertions: { can_execute: false }
      - user: agent:fake
        object: document:kyc-101
        assertions: { can_view: false }

  - name: F4 the person behind the Copilot must be allowed too
    check:
      - user: user:neha
        object: document:kyc-101
        assertions: { can_view: false }
      - user: user:rahul
        object: tool:payment
        context: { amount: 500 }
        assertions: { can_execute: false }

  - name: F5 audit - who can see the customer's KYC file
    list_users:
      - object: document:kyc-101
        user_filter: [{ type: user }]
        assertions:
          can_view: { users: [user:amit, user:rahul] }
      - object: document:kyc-101
        user_filter: [{ type: agent }]
        assertions:
          can_view: { users: [agent:orchestrator, agent:research] }
```

```
docker compose run --rm fga model test --tests tests.fga.yaml
```
**Expected:**
```
Tests 5/5 passing
Checks 17/17 passing
ListObjects 1/1 passing
ListUsers 2/2 passing
```

**Show a failing change:** a developer "simplifies" deletion. In `model.fga` under `type document`, change `define can_delete: owner` to `define can_delete: viewer`, then run the tests again (you don't need to write the model to the store; the tests run locally against the file).

**Expected:**
```
(FAILING) F1 need-to-know - each team sees only its own cases: Checks (4/5 passing)
ⅹ Check(user=user:rahul,relation=can_delete,object=document:kyc-101): expected=false, got=true
Tests 4/5 passing
```
Every viewer could now delete customer files, and the test caught it before production. Put the line back.

**Say:** "This file runs in CI on every pull request. A model change that breaks a compliance rule never reaches production. The policy has a diff, a reviewer, tests and a version."

**F8 resolved.**

---