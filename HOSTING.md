# Mailslot Hosting Plan

## Runtime Shape

The current mailslot deployment only needs:

- the `@mailslot/server` HTTP process on port `8800`
- a persistent SQLite file or volume
- outbound HTTPS access to a Stacks API for read-only contract calls
- inbound HTTPS from humans and agents

The server now includes the reservoir signing logic directly. A separate StackFlow node is no longer required for the current mailbox flow.

## Recommended PoC Targets

### Option A: Fly.io

Good default when we want the fastest path to a public demo:

- one app
- one persistent volume mounted at `/data`
- automatic TLS
- simple `fly deploy`
- good fit for a single-region controlled beta

Minimal shape:

```toml
app = "mailslot"

[build]
  dockerfile = "Dockerfile"

[[services]]
  internal_port = 8800
  protocol = "tcp"
  [[services.ports]]
    port = 80
    handlers = ["http"]
  [[services.ports]]
    port = 443
    handlers = ["tls", "http"]

[[mounts]]
  source = "mailslot_data"
  destination = "/data"
```

Current repo default:

- [`fly.toml`](./fly.toml) is configured for one `shared-cpu-1x` machine with `512MB` RAM
- one persistent volume at `/data`
- `/health` check enabled
- `min_machines_running = 1` so the app stays warm for inbox polling and web usage

### Option B: DigitalOcean Droplet

Good default when we want SSH access and simple local-disk persistence:

- Ubuntu 24.04
- Caddy or nginx in front of port `8800`
- SQLite stored on the droplet disk

Example Caddy file:

```caddy
mailslot.locker {
    reverse_proxy 127.0.0.1:8800
}
```

## Environment Checklist

Required or strongly recommended server vars:

```bash
MAILSLOT_HOST=0.0.0.0
MAILSLOT_PORT=8800
MAILSLOT_DB_FILE=/data/mailslot.db
MAILSLOT_STACKS_NETWORK=mainnet
MAILSLOT_RESERVOIR_CONTRACT_ID=SP....sm-reservoir
MAILSLOT_SF_CONTRACT_ID=SP....sm-stackflow
MAILSLOT_MESSAGE_PRICE_SATS=1000
MAILSLOT_MIN_FEE_SATS=100
MAILSLOT_MAX_PENDING_PER_SENDER=5
MAILSLOT_MAX_PENDING_PER_RECIPIENT=20
MAILSLOT_MAX_DEFERRED_PER_SENDER=5
MAILSLOT_MAX_DEFERRED_PER_RECIPIENT=20
MAILSLOT_MAX_DEFERRED_GLOBAL=200
MAILSLOT_DEFERRED_MESSAGE_TTL_MS=86400000
MAILSLOT_MAX_BORROW_PER_TAP=100000
MAILSLOT_AUTH_AUDIENCE=https://mailslot.locker
MAILSLOT_ALLOWED_ORIGINS=https://mailslot.locker
MAILSLOT_RATE_LIMIT_WINDOW_MS=60000
MAILSLOT_RATE_LIMIT_MAX=120
MAILSLOT_RATE_LIMIT_AUTH_MAX=60
MAILSLOT_RATE_LIMIT_SEND_MAX=20
MAILSLOT_RATE_LIMIT_ADMIN_MAX=10
MAILSLOT_ENABLE_BROWSER_DECRYPT_KEY=false
```

Optional identity vars:

```bash
MAILSLOT_SERVER_PRIVATE_KEY=<32-byte-hex>
MAILSLOT_SERVER_STX_ADDRESS=SP...
```

Optional webhook / watcher integration:

```bash
MAILSLOT_DISPUTE_WEBHOOK_TOKEN=<random-shared-secret>
```

If the identity vars are omitted, the server generates a signer key once and persists it in the SQLite `meta` table. Do not rotate or discard that DB file unless you also plan to update the on-chain agent registration.

## Persistence Notes

- Keep `mailslot.db`, `mailslot.db-wal`, and `mailslot.db-shm` together.
- Do not use ephemeral storage for the production DB.
- Back up the DB before container or VM migrations because it contains the persisted signer key and tracked pipe state.
- A live consistent snapshot can be created with [`scripts/backup_db.py`](./scripts/backup_db.py).

Example:

```bash
python3 scripts/backup_db.py /data/mailslot.db /data/backups/mailslot-$(date +%F-%H%M%S).db
```

## Deployment Notes

- `npm install`
- `npm run build --workspaces`
- start `@mailslot/server`
- verify `GET /health`
- verify `GET /status`
- verify `/` serves the web UI

### Fly Deploy Steps

1. Create the app once:

```bash
fly launch --no-deploy
```

2. Create the volume once:

```bash
fly volumes create mailslot_data --region ord --size 1
```

3. Set required secrets/config:

```bash
fly secrets set \
  MAILSLOT_RESERVOIR_CONTRACT_ID=SP....sm-reservoir \
  MAILSLOT_SF_CONTRACT_ID=SP....sm-stackflow
```

Optional if you want a fixed signer identity instead of DB-generated first boot:

```bash
fly secrets set \
  MAILSLOT_SERVER_PRIVATE_KEY=<32-byte-hex> \
  MAILSLOT_SERVER_STX_ADDRESS=SP...
```

4. Deploy:

```bash
fly deploy
```

5. Verify:

```bash
fly status
curl https://<app>.fly.dev/health
curl https://<app>.fly.dev/status
```

6. Attach the production hostname:

```bash
fly certs add mailslot.locker
```

Then point your DNS to Fly and verify:

```bash
curl https://mailslot.locker/health
curl https://mailslot.locker/status
```

## Runtime Config Direction

For the first beta:

- env vars are the bootstrap defaults
- live operational settings are stored in SQLite
- the reservoir deployer can update them through the admin section of the web UI

Current DB-backed runtime settings:

- message price
- minimum fee
- pending queue caps
- deferred queue caps
- deferred TTL
- max borrow offered per tap

Recommended operating model:

- treat env vars as boot defaults and disaster-recovery fallback
- treat the DB as the live source of truth after startup
- include the DB in regular backups because it now contains both signer identity and active runtime config

## Auth, CORS, And Browser Decrypt

- `MAILSLOT_AUTH_AUDIENCE` should be set to the production origin or another stable deployment identifier. Inbox auth payloads are rejected if the audience does not match.
- `MAILSLOT_ALLOWED_ORIGINS` should list the exact web origins allowed to call the API cross-origin. Same-origin requests are always allowed.
- `MAILSLOT_ENABLE_BROWSER_DECRYPT_KEY` should remain `false` for production until wallet-native human decrypt is ready.
- `POST /hooks/dispute` is available for external close/dispute detection systems. Hiro Chainhook is the expected first integration point.

## Current Mainnet Reality

- A fresh reservoir deployment path exists in [`scripts/recover-mainnet-reservoir.mjs`](./scripts/recover-mainnet-reservoir.mjs).
- The currently repaired mainnet mailbox path uses the existing `sm-reservoir` contract plus the restored on-chain agent registration.
- Fresh contract deployment is still blocked until the deployer account has enough STX for deployment gas.
