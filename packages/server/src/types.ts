// Core domain types for Stackmail server

export interface MailMessage {
  id: string;
  from: string;       // sender STX address
  to: string;         // recipient STX address
  subject?: string;   // max 100 chars
  body: string;       // max 10KB, only revealed after claim
  sentAt: number;     // unix ms
  amount: string;     // sats paid by sender (bigint-safe string)
  fee: string;        // server fee taken (bigint-safe string)
  paymentId: string;  // StackFlow forwarding payment ID
}

// Stored in DB before recipient claims — body is withheld
export interface PendingMessage {
  id: string;
  from: string;
  to: string;
  subject?: string;
  body: string;       // stored server-side, not returned until claimed
  sentAt: number;
  amount: string;
  fee: string;
  paymentId: string;
  hashedSecret: string;
  claimed: boolean;
  claimedAt?: number;
}

// What the inbox listing returns (no body until claimed)
export interface InboxEntry {
  id: string;
  from: string;
  subject?: string;
  sentAt: number;
  amount: string;     // payment offered to recipient
  claimed: boolean;
}

export interface InboxQuery {
  limit?: number;
  before?: number;    // unix ms cursor for pagination
  includeClained?: boolean;
}

// Payment parameters returned to sender before they send
export interface PaymentInfo {
  paymentId: string;
  hashedSecret: string;       // hash(R), sender uses this in their StackFlow state update
  amount: string;             // required amount in token base units
  fee: string;                // server fee (amount - recipientAmount)
  recipientAmount: string;    // what recipient receives
  stackflowNodeUrl: string;   // server's StackFlow node URL for the indirect payment
  serverAddress: string;      // server's STX address
  expiresAt: number;          // unix ms — payment info is single-use
}

// Auth challenge signed by recipient for inbox access
export interface InboxAuthPayload {
  action: 'get-inbox' | 'claim-message';
  address: string;    // STX address of signer
  messageId?: string; // required for claim-message
  timestamp: number;  // unix ms
}

export interface Config {
  host: string;
  port: number;
  dbBackend: 'sqlite' | 'postgres';
  dbFile: string;         // sqlite path
  dbUrl?: string;         // postgres connection string
  maxBodyBytes: number;
  maxSubjectLength: number;
  authTimestampTtlMs: number;
  stackflowNodeUrl: string;
  serverStxAddress: string;
  messagePriceSats: string;    // base price per message
  minFeeSats: string;          // minimum server fee
}

export function loadConfig(): Config {
  return {
    host: process.env.STACKMAIL_HOST ?? '127.0.0.1',
    port: parseInt(process.env.STACKMAIL_PORT ?? '8800', 10),
    dbBackend: (process.env.STACKMAIL_DB_BACKEND ?? 'sqlite') as 'sqlite' | 'postgres',
    dbFile: process.env.STACKMAIL_DB_FILE ?? './data/stackmail.db',
    dbUrl: process.env.STACKMAIL_DB_URL,
    maxBodyBytes: parseInt(process.env.STACKMAIL_MAX_BODY_BYTES ?? '10240', 10),
    maxSubjectLength: parseInt(process.env.STACKMAIL_MAX_SUBJECT_LENGTH ?? '100', 10),
    authTimestampTtlMs: parseInt(process.env.STACKMAIL_AUTH_TIMESTAMP_TTL_MS ?? '300000', 10),
    stackflowNodeUrl: process.env.STACKMAIL_STACKFLOW_NODE_URL ?? 'http://127.0.0.1:8787',
    serverStxAddress: process.env.STACKMAIL_SERVER_STX_ADDRESS ?? '',
    messagePriceSats: process.env.STACKMAIL_MESSAGE_PRICE_SATS ?? '1000',
    minFeeSats: process.env.STACKMAIL_MIN_FEE_SATS ?? '100',
  };
}
