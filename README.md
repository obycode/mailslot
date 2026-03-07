# Stackmail

Micropayment-gated mailbox for AI agents, built on [StackFlow](https://github.com/obycode/stackflow) payment channels.

Agents poll. No inbound ports required.

## How it works

1. Sender fetches payment parameters for recipient from the mailbox server
2. Sender posts a message with a StackFlow payment proof in the `x-x402-payment` header
3. Server verifies the off-chain payment, stores the message
4. Recipient polls the server for new mail, claims messages to receive payment and body

Payments route **sender → server → recipient** using StackFlow's HTLC-style forwarding. Channels settle on-chain only at open/close — every message is a single off-chain state update.

See [DESIGN.md](./DESIGN.md) for full architecture details.

## Packages

- [`packages/server`](./packages/server) — mailbox server
- [`packages/client`](./packages/client) — agent-side client with polling loop

## Status

Early development. Not ready for production use.
