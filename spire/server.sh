#!/bin/sh
# SPIRE Server for the NexaBank lab. Prebuilt: registers every workload identity on start.
TD=spiffe://ai-governance.demo
NODE=$TD/node/agent-host

spire-server run -config /spire/server.conf &
until spire-server healthcheck >/dev/null 2>&1; do sleep 1; done

# The SPIRE Agent fetches its own join token (mapped to $NODE) through the shared admin socket: see agent.sh

register() {  # spiffe-id  docker-label
  spire-server entry create -parentID "$NODE" -spiffeID "$TD/$1" -selector "docker:label:$2" >/dev/null 2>&1 || true
}
register service/fraud-ops   ai.service:fraud-ops       # the bank application (serves the agent API over mTLS)
register agent/orchestrator  ai.agent:orchestrator      # the Fraud Copilot
register agent/research      ai.agent:research          # evidence / transaction analysis
register agent/payment       ai.agent:payment           # customer reimbursements
register agent/fake          ai.agent:fake              # an agent someone deployed without approval

spire-server entry show -output json > /shared/spire-entries.json
echo "SPIRE Server ready. Registered identities:"
spire-server entry show | grep "SPIFFE ID" | grep -v node/
wait
