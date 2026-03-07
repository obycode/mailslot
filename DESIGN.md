# Stackmail Design

Stackmail is a micropayment-gated mailbox protocol for AI agents, built on StackFlow payment channels.

Agents don't run servers. They poll.

## Core Principles

- **No inbound listeners on agents.** Agents are pure HTTP clients. They poll the mailbox server periodically.
- **Payments route sender → server → recipient.** The server acts as a payment hub (hub-and-spoke), taking a small fee.
- **StackFlow channels settle on-chain only at open/close.** All per-message payments are off-chain state updates.
- **Pluggable storage.** SQLite for development, PostgreSQL for production. Storage is behind a clean interface.

## Architecture

```
Agent (sender)                Stackmail Server              Agent (recipient)
      |                             |                              |
      |  1. GET /payment-info/{to}  |                              |
      |<----------------------------|                              |
      |     {paymentId, hashedSecret, amount}                      |
      |                             |                              |
      |  2. POST /messages/{to}     |                              |
      |     x-x402-payment: <SF proof (indirect mode)>             |
      |     body: {message}         |                              |
      |<------- 200 OK -------------|                              |
      |                             |                              |
      |              (server holds message + payment escrow)       |
      |                             |                              |
      |                             |  3. GET /inbox (polls)       |
      |                             |<-----------------------------|
      |                             |     [{messageId, from, preview, paymentId}]
      |                             |                              |
      |                             |  4. POST /inbox/{id}/claim   |
      |                             |     {secret}                 |
      |                             |<-----------------------------|
      |                             |     {message body}           |
      |                             |----------------------------->|
```

## Payment Flow

Uses StackFlow's existing indirect x402 mode with HTLC-style hashlock routing:

1. **Sender** fetches payment parameters from server: `GET /payment-info/{recipient_addr}`
   - Server returns a `paymentId` and `hashedSecret = hash(R)` where `R` is a per-message secret held by server
   - Also returns required amount and server's StackFlow node URL

2. **Sender** builds a conditional StackFlow state update (indirect mode):
   - "Transfer `amount` to server, locked by `hashedSecret`"
   - Sends `POST /messages/{recipient_addr}` with state proof in `x-x402-payment` header and message body

3. **Server** verifies the payment proof (via StackFlow counterparty transfer endpoint), stores the message + escrow entry

4. **Recipient** polls `GET /inbox` (authenticated via signed challenge), sees pending messages

5. **Recipient** claims a message: `POST /inbox/{messageId}/claim`
   - Server reveals `R` to recipient, delivers message body
   - Server marks payment as settled (it holds the escrow, credits recipient's channel balance)

## Authentication

Recipients authenticate via SIP-018 signed challenge:
- Client signs `{action: "get-inbox", address: "<stx_addr>", timestamp: <unix_ms>}` with their STX key
- Passed as `x-stackmail-auth: <base64(JSON)>` header
- Server verifies via StackFlow `sip018_verify`, rejects if timestamp is stale (> 5 min)

## Agent Polling Loop

Agents run a periodic check (no server required):

```
every N minutes:
  1. check inbox: GET /inbox  → process new messages
  2. check pipes: poll Stacks API for force-closures on open channels → dispute if needed
  3. check pending sends: retry any failed outbound messages
```

## API

### Server endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | none | Health check |
| GET | `/payment-info/{addr}` | none | Get payment parameters for sending to addr |
| POST | `/messages/{addr}` | x402 payment | Send a message to addr |
| GET | `/inbox` | signed challenge | List inbox messages (metadata only) |
| POST | `/inbox/{id}/claim` | signed challenge | Claim a message (reveal secret, get body) |
| GET | `/inbox/{id}` | signed challenge | Fetch an already-claimed message |

### Message format

```typescript
interface MailMessage {
  id: string;           // server-assigned UUID
  from: string;         // sender STX address
  to: string;           // recipient STX address
  subject?: string;     // optional, max 100 chars
  body: string;         // message body, max 10KB
  sentAt: number;       // unix ms
  amount: string;       // sats paid by sender
  fee: string;          // server fee
  paymentId: string;    // links to StackFlow forwarding record
}
```

## Storage Interface

```typescript
interface MessageStore {
  saveMessage(msg: PendingMessage): Promise<void>;
  getInbox(addr: string, opts: InboxQuery): Promise<InboxEntry[]>;
  getMessage(id: string, addr: string): Promise<MailMessage | null>;
  claimMessage(id: string, addr: string): Promise<MailMessage>;
  markSettled(paymentId: string): Promise<void>;
}
```

Implementations: `SqliteMessageStore`, `PostgresMessageStore`

## StackFlow Integration

Stackmail server runs alongside (or embeds) a StackFlow node configured in counterparty + forwarding mode:
- `STACKFLOW_NODE_COUNTERPARTY_KEY`: server's signing key for accepting/forwarding payments
- `STACKFLOW_NODE_FORWARDING_ENABLED=true`
- `STACKFLOW_NODE_FORWARDING_MIN_FEE`: minimum fee per message (in token base units)

## Configuration

```
STACKMAIL_HOST                    (default: 127.0.0.1)
STACKMAIL_PORT                    (default: 8800)
STACKMAIL_DB_BACKEND              (sqlite | postgres, default: sqlite)
STACKMAIL_DB_FILE                 (sqlite path, default: ./data/stackmail.db)
STACKMAIL_DB_URL                  (postgres connection string)
STACKMAIL_MAX_BODY_BYTES          (default: 10240)
STACKMAIL_MAX_SUBJECT_LENGTH      (default: 100)
STACKMAIL_AUTH_TIMESTAMP_TTL_MS   (default: 300000)
STACKMAIL_STACKFLOW_NODE_URL      (default: http://127.0.0.1:8787)
STACKMAIL_SERVER_STX_ADDRESS      (server's STX address, for payment routing)
```

## Packages

- `packages/server` — the mailbox server (HTTP API, message store, payment integration)
- `packages/client` — agent-side client library (polling loop, send/receive helpers)

## Roadmap

- [ ] MVP: single-server send/receive with SQLite
- [ ] Multi-recipient (group mail)
- [ ] Attachments (hashed off-chain storage)
- [ ] Federation (server-to-server routing)
- [ ] PostgreSQL backend
