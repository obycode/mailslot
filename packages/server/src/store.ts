// Message store interface + SQLite implementation

import type { PendingMessage, InboxEntry, MailMessage, InboxQuery } from './types.js';

export interface MessageStore {
  init(): Promise<void>;
  savePendingMessage(msg: PendingMessage): Promise<void>;
  getPendingMessage(id: string): Promise<PendingMessage | null>;
  getInbox(addr: string, query: InboxQuery): Promise<InboxEntry[]>;
  claimMessage(id: string, addr: string): Promise<MailMessage>;
  getClaimedMessage(id: string, addr: string): Promise<MailMessage | null>;
  markPaymentSettled(paymentId: string): Promise<void>;
  // Payment info lifecycle
  savePendingPaymentInfo(info: {
    paymentId: string;
    hashedSecret: string;
    recipientAddr: string;
    amount: string;
    fee: string;
    expiresAt: number;
  }): Promise<void>;
  getPendingPaymentInfo(paymentId: string): Promise<{
    paymentId: string;
    hashedSecret: string;
    recipientAddr: string;
    amount: string;
    fee: string;
    expiresAt: number;
  } | null>;
}

export class SqliteMessageStore implements MessageStore {
  private db: import('better-sqlite3').Database | null = null;
  private readonly dbFile: string;

  constructor(dbFile: string) {
    this.dbFile = dbFile;
  }

  async init(): Promise<void> {
    const { default: Database } = await import('better-sqlite3');
    this.db = new Database(this.dbFile);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('foreign_keys = ON');
    this.runMigrations();
  }

  private runMigrations(): void {
    const db = this.assertDb();
    db.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS pending_payment_info (
        payment_id TEXT PRIMARY KEY,
        hashed_secret TEXT NOT NULL,
        recipient_addr TEXT NOT NULL,
        amount TEXT NOT NULL,
        fee TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL DEFAULT (unixepoch('now') * 1000)
      );
      CREATE INDEX IF NOT EXISTS idx_ppi_recipient ON pending_payment_info (recipient_addr);
      CREATE INDEX IF NOT EXISTS idx_ppi_expires ON pending_payment_info (expires_at);

      CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        from_addr TEXT NOT NULL,
        to_addr TEXT NOT NULL,
        subject TEXT,
        body TEXT NOT NULL,
        sent_at INTEGER NOT NULL,
        amount TEXT NOT NULL,
        fee TEXT NOT NULL,
        payment_id TEXT NOT NULL,
        hashed_secret TEXT NOT NULL,
        claimed INTEGER NOT NULL DEFAULT 0,
        claimed_at INTEGER,
        payment_settled INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_msg_to ON messages (to_addr, sent_at DESC);
      CREATE INDEX IF NOT EXISTS idx_msg_payment ON messages (payment_id);
    `);
    db.prepare("INSERT OR IGNORE INTO meta VALUES ('version', '1')").run();
  }

  private assertDb(): import('better-sqlite3').Database {
    if (!this.db) throw new Error('Store not initialized — call init() first');
    return this.db;
  }

  async savePendingPaymentInfo(info: {
    paymentId: string;
    hashedSecret: string;
    recipientAddr: string;
    amount: string;
    fee: string;
    expiresAt: number;
  }): Promise<void> {
    const db = this.assertDb();
    db.prepare(`
      INSERT INTO pending_payment_info
        (payment_id, hashed_secret, recipient_addr, amount, fee, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(info.paymentId, info.hashedSecret, info.recipientAddr, info.amount, info.fee, info.expiresAt);
  }

  async getPendingPaymentInfo(paymentId: string): Promise<{
    paymentId: string;
    hashedSecret: string;
    recipientAddr: string;
    amount: string;
    fee: string;
    expiresAt: number;
  } | null> {
    const db = this.assertDb();
    const row = db.prepare('SELECT * FROM pending_payment_info WHERE payment_id = ?').get(paymentId) as Record<string, unknown> | undefined;
    if (!row) return null;
    return {
      paymentId: row.payment_id as string,
      hashedSecret: row.hashed_secret as string,
      recipientAddr: row.recipient_addr as string,
      amount: row.amount as string,
      fee: row.fee as string,
      expiresAt: row.expires_at as number,
    };
  }

  async savePendingMessage(msg: PendingMessage): Promise<void> {
    const db = this.assertDb();
    db.prepare(`
      INSERT INTO messages
        (id, from_addr, to_addr, subject, body, sent_at, amount, fee, payment_id, hashed_secret, claimed)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).run(msg.id, msg.from, msg.to, msg.subject ?? null, msg.body, msg.sentAt, msg.amount, msg.fee, msg.paymentId, msg.hashedSecret);
  }

  async getPendingMessage(id: string): Promise<PendingMessage | null> {
    const db = this.assertDb();
    const row = db.prepare('SELECT * FROM messages WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToPending(row);
  }

  async getInbox(addr: string, query: InboxQuery): Promise<InboxEntry[]> {
    const db = this.assertDb();
    const limit = Math.min(query.limit ?? 50, 100);
    const before = query.before ?? Date.now() + 1000;
    const includeClained = query.includeClained ?? false;

    const claimedClause = includeClained ? '' : 'AND claimed = 0';
    const rows = db.prepare(`
      SELECT id, from_addr, subject, sent_at, amount, claimed
      FROM messages
      WHERE to_addr = ? AND sent_at < ? ${claimedClause}
      ORDER BY sent_at DESC
      LIMIT ?
    `).all(addr, before, limit) as Record<string, unknown>[];

    return rows.map(row => ({
      id: row.id as string,
      from: row.from_addr as string,
      subject: row.subject as string | undefined,
      sentAt: row.sent_at as number,
      amount: row.amount as string,
      claimed: Boolean(row.claimed),
    }));
  }

  async claimMessage(id: string, addr: string): Promise<MailMessage> {
    const db = this.assertDb();
    const row = db.prepare('SELECT * FROM messages WHERE id = ? AND to_addr = ?').get(id, addr) as Record<string, unknown> | undefined;
    if (!row) throw new Error('message-not-found');
    if (row.claimed) throw new Error('already-claimed');

    const now = Date.now();
    db.prepare('UPDATE messages SET claimed = 1, claimed_at = ? WHERE id = ?').run(now, id);

    const pending = this.rowToPending(row);
    return {
      id: pending.id,
      from: pending.from,
      to: pending.to,
      subject: pending.subject,
      body: pending.body,
      sentAt: pending.sentAt,
      amount: pending.amount,
      fee: pending.fee,
      paymentId: pending.paymentId,
    };
  }

  async getClaimedMessage(id: string, addr: string): Promise<MailMessage | null> {
    const db = this.assertDb();
    const row = db.prepare('SELECT * FROM messages WHERE id = ? AND to_addr = ? AND claimed = 1').get(id, addr) as Record<string, unknown> | undefined;
    if (!row) return null;
    const pending = this.rowToPending(row);
    return {
      id: pending.id,
      from: pending.from,
      to: pending.to,
      subject: pending.subject,
      body: pending.body,
      sentAt: pending.sentAt,
      amount: pending.amount,
      fee: pending.fee,
      paymentId: pending.paymentId,
    };
  }

  async markPaymentSettled(paymentId: string): Promise<void> {
    const db = this.assertDb();
    db.prepare('UPDATE messages SET payment_settled = 1 WHERE payment_id = ?').run(paymentId);
  }

  private rowToPending(row: Record<string, unknown>): PendingMessage {
    return {
      id: row.id as string,
      from: row.from_addr as string,
      to: row.to_addr as string,
      subject: row.subject as string | undefined,
      body: row.body as string,
      sentAt: row.sent_at as number,
      amount: row.amount as string,
      fee: row.fee as string,
      paymentId: row.payment_id as string,
      hashedSecret: row.hashed_secret as string,
      claimed: Boolean(row.claimed),
      claimedAt: row.claimed_at as number | undefined,
    };
  }
}
