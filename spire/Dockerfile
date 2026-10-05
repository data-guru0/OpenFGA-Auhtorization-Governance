FROM ghcr.io/spiffe/spire-server:1.11.2 AS server
FROM ghcr.io/spiffe/spire-agent:1.11.2 AS agent

FROM alpine:3.20
COPY --from=server /opt/spire/bin/spire-server /usr/local/bin/spire-server
COPY --from=agent /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
COPY server.conf agent.conf server.sh agent.sh /spire/
