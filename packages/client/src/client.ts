// Stackmail client — all operations an agent needs, no server required

import type {
  ClientConfig,
  InboxEntry,
  MailMessage,
  PaymentInfo,
  PollResult,
  SendOptions,
} from './types.js';

export class StackmailClient {
  private readonly config: ClientConfig;

  constructor(config: ClientConfig) {
    this.config = config;
  }

  /**
   * Send a message to a recipient.
   * Fetches payment info from the server, builds a payment proof, posts the message.
   */
  async send(opts: SendOptions): Promise<{ messageId: string }> {
    const serverUrl = opts.serverUrl ?? this.config.serverUrl;

    // 1. Get payment parameters
    const paymentInfo = await this.fetchPaymentInfo(opts.to, serverUrl);

    // 2. Build x402 payment proof (caller-supplied — integrates with their StackFlow wallet)
    const paymentProof = await this.config.paymentProofBuilder(paymentInfo);

    // 3. Send the message
    const res = await fetch(`${serverUrl}/messages/${encodeURIComponent(opts.to)}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-x402-payment': paymentProof,
      },
      body: JSON.stringify({
        from: this.config.address,
        subject: opts.subject,
        body: opts.body,
      }),
      signal: AbortSignal.timeout(30_000),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new StackmailError(res.status, String(body['error'] ?? 'send-failed'), body);
    }

    const data = await res.json() as Record<string, unknown>;
    return { messageId: String(data['messageId'] ?? paymentInfo.paymentId) };
  }

  /**
   * Poll inbox for new messages. Returns metadata only (no body).
   * Caller can then claim individual messages to get the body + payment.
   */
  async getInbox(opts: { limit?: number; before?: number; includeClaimed?: boolean } = {}): Promise<InboxEntry[]> {
    const url = new URL(`${this.config.serverUrl}/inbox`);
    if (opts.limit) url.searchParams.set('limit', String(opts.limit));
    if (opts.before) url.searchParams.set('before', String(opts.before));
    if (opts.includeClaimed) url.searchParams.set('claimed', 'true');

    const authHeader = await this.buildAuthHeader('get-inbox');

    const res = await fetch(url.toString(), {
      headers: { 'x-stackmail-auth': authHeader },
      signal: AbortSignal.timeout(15_000),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new StackmailError(res.status, String(body['error'] ?? 'inbox-fetch-failed'), body);
    }

    const data = await res.json() as { messages: InboxEntry[] };
    return data.messages ?? [];
  }

  /**
   * Claim a message — reveals the payment secret to the server (triggering
   * channel credit) and returns the full message body.
   */
  async claimMessage(messageId: string): Promise<{ message: MailMessage; secret: string | null }> {
    const authHeader = await this.buildAuthHeader('claim-message', messageId);

    const res = await fetch(`${this.config.serverUrl}/inbox/${encodeURIComponent(messageId)}/claim`, {
      method: 'POST',
      headers: { 'x-stackmail-auth': authHeader },
      signal: AbortSignal.timeout(15_000),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new StackmailError(res.status, String(body['error'] ?? 'claim-failed'), body);
    }

    const data = await res.json() as { message: MailMessage; secret: string | null };
    return { message: data.message, secret: data.secret ?? null };
  }

  /**
   * Fetch an already-claimed message.
   */
  async getMessage(messageId: string): Promise<MailMessage> {
    const authHeader = await this.buildAuthHeader('get-inbox');

    const res = await fetch(`${this.config.serverUrl}/inbox/${encodeURIComponent(messageId)}`, {
      headers: { 'x-stackmail-auth': authHeader },
      signal: AbortSignal.timeout(15_000),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new StackmailError(res.status, String(body['error'] ?? 'get-message-failed'), body);
    }

    const data = await res.json() as { message: MailMessage };
    return data.message;
  }

  /**
   * Convenience: poll inbox and auto-claim all unclaimed messages.
   * This is the core of the agent polling loop.
   */
  async poll(opts: { limit?: number } = {}): Promise<PollResult> {
    const entries = await this.getInbox({ limit: opts.limit ?? 20 });
    const unclaimed = entries.filter(e => !e.claimed);

    const claimedMessages: MailMessage[] = [];
    const errors: Array<{ messageId: string; error: string }> = [];

    for (const entry of unclaimed) {
      try {
        const { message } = await this.claimMessage(entry.id);
        claimedMessages.push(message);
      } catch (err) {
        errors.push({
          messageId: entry.id,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    return {
      newMessages: entries,
      claimedMessages,
      errors,
    };
  }

  private async fetchPaymentInfo(recipientAddr: string, serverUrl: string): Promise<PaymentInfo> {
    const res = await fetch(`${serverUrl}/payment-info/${encodeURIComponent(recipientAddr)}`, {
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new StackmailError(res.status, String(body['error'] ?? 'payment-info-failed'), body);
    }

    return res.json() as Promise<PaymentInfo>;
  }

  private async buildAuthHeader(
    action: 'get-inbox' | 'claim-message',
    messageId?: string,
  ): Promise<string> {
    const payload = {
      action,
      address: this.config.address,
      ...(messageId ? { messageId } : {}),
      timestamp: Date.now(),
    };

    const message = JSON.stringify(payload);
    const signature = await this.config.signer(message);

    return Buffer.from(JSON.stringify({ payload, signature })).toString('base64');
  }
}

export class StackmailError extends Error {
  readonly statusCode: number;
  readonly reason: string;
  readonly details: Record<string, unknown>;

  constructor(statusCode: number, reason: string, details: Record<string, unknown> = {}) {
    super(`Stackmail error ${statusCode}: ${reason}`);
    this.name = 'StackmailError';
    this.statusCode = statusCode;
    this.reason = reason;
    this.details = details;
  }
}
