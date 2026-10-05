# NexaBank Fraud Ops: OpenFGA Authorization Governance Lab

NexaBank built an **AI Fraud Copilot**, and Risk & Compliance blocked go-live with six access findings. In class you build OpenFGA step by step, for people (Keycloak) and AI agents (SPIFFE/SPIRE), until the real app and its AI agents pass the review.

## Start

1. Docker Desktop is running.
2. `.env` contains your `GROQ_API_KEY`. Leave the authorization settings at their starting values:
   ```
   AUTHZ_MODE=legacy
   FGA_STORE_ID=
   FGA_MODEL_ID=
   FGA_SYNC_KEYCLOAK_GROUPS=false
   FGA_ON_BEHALF_OF=false
   ```
3. Start the prebuilt system:
   ```
   docker compose up -d --build
   ```
4. Wait about 40 seconds, then check:
   ```
   docker compose ps
   ```
   **Expected:** `keycloak`, `spire-server`, `spire-agent`, `fraud-ops` and the four `agent-*` containers are all **Up**

Wait about 40 s, then open the services:

| What | URL | Login |
|---|---|---|
| NexaBank Fraud Ops | http://localhost:8000 | `rahul`, `amit`, `neha`, `sudhanshu` / `password` |
| Keycloak admin console | http://localhost:8180 | `admin` / `admin` |
| OpenFGA API (after you start it in class) | http://localhost:8090 | none |
| OpenFGA Playground | https://play.fga.dev/sandbox/?fga_api_host=127.0.0.1%3A8090&fga_api_scheme=http | Allow "local network access" |



## Files

```
docker-compose.yml     all services; OpenFGA is behind the "openfga" profile and the CLI behind "tools"
.env                   Groq key + the authorization switches you flip in class
keycloak/              realm import (users, groups, roles, the nexabank-app OIDC client)
spire/                 SPIRE Server + Agent config; server.sh registers every workload identity
app/server.py          the Fraud Ops app: login, mTLS agent API, legacy rules, OpenFGA integration
app/agents.py          the AI agents: Copilot (tool calling), research, payment, rogue
app/common.py          SVID fetching and rotation, mTLS client and server, Groq client
app/bank_data.json     cases, documents (one carries a prompt injection), reports, transactions
app/static/index.html  the Fraud Ops web UI
openfga/               empty: you create model.fga, tuples-*.yaml and tests.fga.yaml here in class
```

## Stop / reset

```
docker compose --profile openfga --profile tools down -v
```
See Appendix D of the guide to reset to the start of class.
