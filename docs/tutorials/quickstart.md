# Run the local GoBGP stack

This walkthrough uses the current default GoBGP deployment. Run commands from
the repository root; router setup and rustbgpd qualification are separate guides.

## Docker Compose (Recommended)

```bash
# Clone
git clone https://github.com/lance0/prefixd.git
cd prefixd

# Configure
cp configs/prefixd.yaml.example configs/prefixd.yaml
# Edit configs/prefixd.yaml, inventory.yaml, playbooks.yaml

# Generate API token
export PREFIXD_API_TOKEN=$(openssl rand -hex 32)
echo "PREFIXD_API_TOKEN=$PREFIXD_API_TOKEN" >> .env

# Start
docker compose up -d

# Create admin operator (for dashboard login)
docker compose exec prefixd prefixdctl operators create \
  --username admin --role admin

# Verify
curl http://localhost/v1/health
open http://localhost
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| nginx | 80 | Reverse proxy (single entrypoint) |
| grafana | 3001 | Monitoring dashboards |
| prometheus | 9091 | Metrics storage |
| gobgp | 179 | BGP (to routers) |
| gobgp | 50051 | gRPC API (published to host) |
| postgres | 5432 | Database |

> **Note:** The dashboard and API are not exposed directly. All HTTP and WebSocket traffic goes through nginx on port 80.

> **Config editing in Docker:** The default `docker-compose.yml` mounts `./configs:/etc/prefixd` (writable) so the dashboard config editors (playbooks, alerting, correlation) work out of the box. Writes use atomic temp-file + fsync + rename with `.bak` backups, and all PUT endpoints are admin-only with validation. For hardened deployments, add `:ro` to the mount and edit configs on the host, then reload via `POST /v1/config/reload`.

Continue with [authentication](../how-to/deployment.md#authentication-setup),
[router configuration](../how-to/deployment.md#router-configuration), and
[speaker support](../reference/speaker-backends.md).
