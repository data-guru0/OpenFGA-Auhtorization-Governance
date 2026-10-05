#!/bin/sh
# SPIRE Agent. On every start it fetches a fresh trust bundle and a fresh one-time join token
# straight from the SPIRE Server (through the server's admin socket), then attests.
# A join token can't be reused, so this is what lets the agent heal itself after a crash,
# a laptop sleep or an expired node SVID: Docker restarts it and it simply attests again.
SERVER_SOCKET=/run/spire/server/api.sock
until spire-server healthcheck -socketPath $SERVER_SOCKET >/dev/null 2>&1; do sleep 1; done

rm -rf /var/lib/spire/agent && mkdir -p /var/lib/spire/agent /run/spire/sockets
spire-server bundle show -socketPath $SERVER_SOCKET > /var/lib/spire/agent/bootstrap-bundle.pem
TOKEN=$(spire-server token generate -socketPath $SERVER_SOCKET -spiffeID spiffe://ai-governance.demo/node/agent-host | sed 's/^Token: //')

exec spire-agent run -config /spire/agent.conf -joinToken "$TOKEN"
