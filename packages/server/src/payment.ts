// Payment service — interfaces with StackFlow node for payment verification and forwarding

import { randomBytes, createHash } from 'node:crypto';
import type { PaymentInfo, Config } from './types.js';

export class PaymentError extends Error {
  readonly statusCode: number;
  readonly reason: string;

  constructor(statusCode: number, message: string, reason: string) {
    super(message);
    this.name = 'PaymentError';
    this.statusCode = statusCode;
    this.reason = reason;
  }
}

function generateSecret(): { secret: string; hashedSecret: string } {
  const secret = `0x${randomBytes(32).toString('hex')}`;
  const bytes = Buffer.from(secret.slice(2), 'hex');
  const hashedSecret = `0x${createHash('sha256').update(bytes).digest('hex')}`;
  return { secret, hashedSecret };
}

function generatePaymentId(): string {
  return `sm-${Date.now().toString(36)}-${randomBytes(6).toString('hex')}`;
}

export interface PendingPaymentInfo {
  paymentId: string;
  secret: string;           // held server-side, revealed to recipient on claim
  hashedSecret: string;     // sent to sender for their HTLC state update
  recipientAddr: string;
  amount: string;
  fee: string;
  recipientAmount: string;
  expiresAt: number;
}

export class PaymentService {
  private readonly config: Config;
  // In-memory store for secrets (paymentId -> secret) — persisted separately in DB
  private readonly secrets = new Map<string, string>();

  constructor(config: Config) {
    this.config = config;
  }

  /**
   * Generate payment parameters for a sender who wants to message a recipient.
   * Returns the public PaymentInfo (for the sender) and retains the secret server-side.
   */
  generatePaymentInfo(recipientAddr: string): { public: PaymentInfo; internal: PendingPaymentInfo } {
    const { secret, hashedSecret } = generateSecret();
    const paymentId = generatePaymentId();
    const amount = this.config.messagePriceSats;
    const fee = this.config.minFeeSats;
    const recipientAmount = (BigInt(amount) - BigInt(fee)).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 min

    this.secrets.set(paymentId, secret);

    const internal: PendingPaymentInfo = {
      paymentId,
      secret,
      hashedSecret,
      recipientAddr,
      amount,
      fee,
      recipientAmount,
      expiresAt,
    };

    const publicInfo: PaymentInfo = {
      paymentId,
      hashedSecret,
      amount,
      fee,
      recipientAmount,
      stackflowNodeUrl: this.config.stackflowNodeUrl,
      serverAddress: this.config.serverStxAddress,
      expiresAt,
    };

    return { public: publicInfo, internal };
  }

  /**
   * Verify an incoming x402 payment proof by calling the StackFlow node.
   * Returns the paymentId extracted from the proof.
   */
  async verifyIncomingPayment(proof: unknown): Promise<{ paymentId: string; amount: string }> {
    // The proof is an indirect-mode x402 payment: { mode: 'indirect', paymentId, expectedAmount, ... }
    if (!isRecord(proof)) {
      throw new PaymentError(400, 'invalid payment proof', 'invalid-proof');
    }

    if (proof['mode'] !== 'indirect') {
      throw new PaymentError(400, 'only indirect payment mode is supported', 'unsupported-mode');
    }

    const paymentId = proof['paymentId'];
    if (typeof paymentId !== 'string' || !paymentId) {
      throw new PaymentError(400, 'paymentId is required', 'missing-payment-id');
    }

    // Poll StackFlow node for the forwarding payment record
    const sfUrl = `${this.config.stackflowNodeUrl}/forwarding/payments?paymentId=${encodeURIComponent(paymentId)}`;
    let sfResponse: Record<string, unknown>;
    try {
      const res = await fetch(sfUrl, { signal: AbortSignal.timeout(10_000) });
      if (!res.ok) {
        throw new PaymentError(402, 'payment not found', 'payment-not-found');
      }
      sfResponse = await res.json() as Record<string, unknown>;
    } catch (err) {
      if (err instanceof PaymentError) throw err;
      throw new PaymentError(502, 'could not reach StackFlow node', 'stackflow-unavailable');
    }

    const status = sfResponse['status'];
    if (status !== 'completed') {
      throw new PaymentError(402, `payment not completed: ${status}`, 'payment-pending');
    }

    const incomingAmount = sfResponse['incomingAmount'];
    if (typeof incomingAmount !== 'string') {
      throw new PaymentError(502, 'StackFlow node returned unexpected response', 'invalid-stackflow-response');
    }

    return { paymentId, amount: incomingAmount };
  }

  /**
   * Reveal the secret for a paymentId so the recipient can claim their funds.
   * Calls POST /forwarding/reveal on the StackFlow node.
   */
  async revealSecretForPayment(paymentId: string): Promise<string> {
    const secret = this.secrets.get(paymentId);
    if (!secret) {
      throw new PaymentError(404, 'payment secret not found', 'secret-not-found');
    }

    const sfUrl = `${this.config.stackflowNodeUrl}/forwarding/reveal`;
    try {
      const res = await fetch(sfUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ paymentId, secret }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as Record<string, unknown>;
        throw new PaymentError(502, `StackFlow reveal failed: ${body['reason'] ?? res.status}`, 'reveal-failed');
      }
    } catch (err) {
      if (err instanceof PaymentError) throw err;
      throw new PaymentError(502, 'could not reach StackFlow node', 'stackflow-unavailable');
    }

    return secret;
  }

  /** Load an in-memory secret back (e.g. after restart from DB) */
  restoreSecret(paymentId: string, secret: string): void {
    this.secrets.set(paymentId, secret);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
