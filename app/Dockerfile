FROM ghcr.io/spiffe/spire-agent:1.11.2 AS spire

# One image for the Fraud Ops app and every AI agent. The spire-agent binary is only used as a
# Workload API client: it fetches this container's X.509-SVID from the SPIRE Agent's socket.
FROM python:3.12-slim
COPY --from=spire /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
WORKDIR /app
COPY . .
CMD ["python", "-u", "server.py"]
