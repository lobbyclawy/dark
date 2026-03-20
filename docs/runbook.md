# dark Operations Runbook

## Table of Contents

- [Deployment](#deployment)
- [Configuration](#configuration)
- [Monitoring](#monitoring)
- [Backup & Restore](#backup--restore)
- [Incident Response](#incident-response)
- [Performance Tuning](#performance-tuning)

---

## Deployment

### Prerequisites

- Docker and Docker Compose v2+
- At least 4 GB RAM (2 GB for Bitcoin Core, 1 GB for dark, 1 GB for monitoring)
- 100 GB+ disk for mainnet Bitcoin data (minimal for regtest/testnet)

### Quick Start (Development / Regtest)

```bash
# Clone and configure
git clone https://github.com/lobbyclawy/dark.git
cd dark
cp config.example.toml config.toml

# Start all services
docker compose -f docker-compose.prod.yml up -d

# Verify
curl -s http://localhost:9090/health | jq .
# → {"status":"ok","version":"0.1.0","uptime_secs":5}
```

### Production Deployment

1. **Configure secrets:**
   ```bash
   cp config.example.toml config.toml
   # Edit config.toml: set bitcoin.network = "mainnet", strong RPC credentials,
   # enable TLS, set admin_token, etc.
   ```

2. **Set environment variables:**
   ```bash
   export GRAFANA_PASSWORD="<strong-password>"
   ```

3. **Build and start:**
   ```bash
   docker compose -f docker-compose.prod.yml up -d --build
   ```

4. **Verify services:**
   ```bash
   docker compose -f docker-compose.prod.yml ps
   curl -s http://localhost:9090/health
   curl -s http://localhost:9090/metrics | head -20
   ```

### Upgrading

```bash
git pull origin main
docker compose -f docker-compose.prod.yml up -d --build
# Monitor logs for errors
docker logs -f dark-server --tail 100
```

---

## Configuration

See `config.example.toml` for all available fields. Key production settings:

| Setting | Recommended | Notes |
|---------|------------|-------|
| `bitcoin.network` | `mainnet` | Match your Bitcoin Core config |
| `server.tls_enabled` | `true` | Always use TLS in production |
| `server.require_auth` | `true` | Enforce authentication |
| `database.backend` | `sqlite` | Simple; postgres for high scale |
| `metrics.enabled` | `true` | Enable Prometheus metrics |
| `metrics.endpoint` | `0.0.0.0:9090` | Metrics + health port |
| `health.endpoint` | `0.0.0.0:9090` | Shared with metrics |

---

## Monitoring

### Health Check

```bash
# Simple liveness check
curl -sf http://localhost:9090/health

# JSON response:
# {"status":"ok","version":"0.1.0","uptime_secs":3600}
```

### Prometheus Metrics

Available at `http://localhost:9090/metrics`. Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `dark_rounds_total` | Counter | Total rounds initiated |
| `dark_rounds_completed_total` | Counter | Rounds completed successfully |
| `dark_rounds_failed_total` | Counter | Rounds that failed |
| `dark_active_rounds` | Gauge | Currently active rounds |
| `dark_participants_total` | Counter | Total participants registered |
| `dark_active_participants` | Gauge | Participants in active rounds |
| `dark_vtxos_created_total` | Counter | Total VTXOs created |
| `dark_vtxos_active` | Gauge | Currently active VTXOs |
| `dark_vtxos_spent_total` | Counter | Total VTXOs spent |
| `dark_sweeps_total` | Counter | Sweep operations executed |
| `dark_sweeps_vtxos_reclaimed_total` | Counter | VTXOs reclaimed via sweeps |

### Grafana

Access at `http://localhost:3000` (default: admin / `$GRAFANA_PASSWORD`).

Add Prometheus as a data source:
- URL: `http://prometheus:9090`
- Access: Server (default)

### Alerting Rules (Prometheus)

Example alert rules to add in `prometheus.yml`:

```yaml
groups:
  - name: dark
    rules:
      - alert: ArkdDown
        expr: up{job="dark"} == 0
        for: 1m
        labels:
          severity: critical
      - alert: HighRoundFailureRate
        expr: rate(dark_rounds_failed_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
```

---

## Backup & Restore

### SQLite Database Backup

dark uses SQLite with WAL (Write-Ahead Logging). Safe backup procedure:

```bash
# Option 1: SQLite online backup (recommended — safe during writes)
docker exec dark-server sqlite3 /data/dark.db ".backup '/data/backup.db'"
docker cp dark-server:/data/backup.db ./backups/dark-$(date +%Y%m%d).db

# Option 2: File copy with WAL checkpoint (requires brief pause)
docker exec dark-server sqlite3 /data/dark.db "PRAGMA wal_checkpoint(TRUNCATE);"
docker cp dark-server:/data/dark.db ./backups/dark-$(date +%Y%m%d).db
```

### Restore

```bash
# Stop dark
docker compose -f docker-compose.prod.yml stop dark

# Replace database
docker cp ./backups/dark-20260101.db dark-server:/data/dark.db

# Restart
docker compose -f docker-compose.prod.yml start dark
```

### Bitcoin Core Data

Bitcoin Core data is stored in the `bitcoin_data` volume. For mainnet:

```bash
# Backup wallet (if using Bitcoin Core wallet)
docker exec dark-bitcoin bitcoin-cli -rpcuser=dark -rpcpassword=dark backupwallet /tmp/wallet.bak
docker cp dark-bitcoin:/tmp/wallet.bak ./backups/

# Full data backup (stop first)
docker compose -f docker-compose.prod.yml stop bitcoin
docker run --rm -v dark_bitcoin_data:/data -v $(pwd)/backups:/backup \
    alpine tar czf /backup/bitcoin-data.tar.gz /data
docker compose -f docker-compose.prod.yml start bitcoin
```

### Automated Backups (cron)

```bash
# Add to crontab: daily backup at 3 AM
0 3 * * * cd /path/to/dark && docker exec dark-server sqlite3 /data/dark.db ".backup '/data/backup.db'" && docker cp dark-server:/data/backup.db /backups/dark-$(date +\%Y\%m\%d).db
```

---

## Incident Response

### dark Not Starting

1. Check logs: `docker logs dark-server --tail 50`
2. Verify config: `docker exec dark-server cat /etc/dark/config.toml`
3. Check port conflicts: `docker compose -f docker-compose.prod.yml ps`
4. Verify Bitcoin Core is healthy: `docker exec dark-bitcoin bitcoin-cli -regtest -rpcuser=dark -rpcpassword=dark getblockchaininfo`

### High Memory Usage

1. Check current usage: `docker stats dark-server`
2. Review resource limits in `docker-compose.prod.yml`
3. Consider reducing `server.max_connections`
4. Check for VTXO accumulation: `curl -s http://localhost:9090/metrics | grep vtxos_active`

### Round Failures

1. Check metrics: `curl -s http://localhost:9090/metrics | grep rounds_failed`
2. Review logs: `docker logs dark-server --tail 200 | grep -i "round\|error"`
3. Verify Bitcoin Core connectivity
4. Check if minimum participants are being met

### Database Corruption

1. Stop dark: `docker compose -f docker-compose.prod.yml stop dark`
2. Check integrity: `docker exec dark-server sqlite3 /data/dark.db "PRAGMA integrity_check;"`
3. If corrupt, restore from backup (see [Restore](#restore))
4. If no backup, attempt recovery: `sqlite3 /data/dark.db ".recover" | sqlite3 /data/recovered.db`

### Bitcoin Core Sync Issues

1. Check sync progress: `docker exec dark-bitcoin bitcoin-cli -rpcuser=dark -rpcpassword=dark getblockchaininfo`
2. Check disk space: `docker exec dark-bitcoin df -h /home/bitcoin/.bitcoin`
3. Consider increasing `dbcache` for faster initial sync

---

## Performance Tuning

### dark Server

| Parameter | Default | Tuning Notes |
|-----------|---------|--------------|
| `server.max_connections` | 1000 | Lower if memory-constrained |
| `server.request_timeout_secs` | 30 | Increase for slow networks |
| `ark.round_duration_secs` | 60 | Longer = more batching, higher latency |
| `ark.max_participants` | 100 | Higher = larger trees, more memory per round |
| `database.max_connections` | 10 | Match to expected concurrent load |

### Docker Resources

```yaml
# docker-compose.prod.yml
deploy:
  resources:
    limits:
      cpus: "2.0"      # Increase for more throughput
      memory: 1G        # Increase if handling many concurrent rounds
```

### SQLite Tuning

dark applies these PRAGMAs automatically, but you can verify:

```sql
PRAGMA journal_mode = WAL;      -- Write-Ahead Logging
PRAGMA synchronous = NORMAL;    -- Balance safety/performance
PRAGMA cache_size = -64000;     -- 64 MB page cache
PRAGMA busy_timeout = 5000;     -- 5s retry on lock contention
```

### Bitcoin Core

For mainnet production:

```
-dbcache=4096        # 4 GB UTXO cache (faster validation)
-maxmempool=300      # 300 MB mempool
-maxconnections=40   # Limit peer connections
```

---

## Log Analysis

### Structured Log Queries

```bash
# Recent errors
docker logs dark-server --since 1h 2>&1 | grep -i error

# Round activity
docker logs dark-server --since 1h 2>&1 | grep -i round

# Slow requests
docker logs dark-server --since 1h 2>&1 | grep -i "timeout\|slow"
```

### Log Rotation

Docker json-file driver is configured with rotation in `docker-compose.prod.yml`:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "50m"
    max-file: "5"
```

Total log storage per container: 250 MB max.
