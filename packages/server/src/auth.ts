// SIP-018 signed challenge authentication for inbox access

import type { InboxAuthPayload, Config } from './types.js';

export class AuthError extends Error {
  readonly statusCode: number;
  readonly reason: string;

  constructor(statusCode: number, message: string, reason: string) {
    super(message);
    this.name = 'AuthError';
    this.statusCode = statusCode;
    this.reason = reason;
  }
}

/**
 * Parse and validate the x-stackmail-auth header.
 *
 * Header value: base64(JSON({ payload: InboxAuthPayload, signature: "0x..." }))
 *
 * Verification is done by calling the StackFlow node's SIP-018 verify endpoint,
 * which handles the Stacks signature verification against the STX address.
 */
export async function verifyInboxAuth(
  authHeader: string,
  stackflowNodeUrl: string,
  config: Config,
): Promise<InboxAuthPayload> {
  let parsed: { payload: InboxAuthPayload; signature: string };
  try {
    const json = Buffer.from(authHeader, 'base64').toString('utf-8');
    parsed = JSON.parse(json) as { payload: InboxAuthPayload; signature: string };
  } catch {
    throw new AuthError(401, 'invalid auth header encoding', 'invalid-auth-encoding');
  }

  const { payload, signature } = parsed;

  if (!payload?.action || !payload?.address || !payload?.timestamp) {
    throw new AuthError(401, 'auth payload missing required fields', 'invalid-auth-payload');
  }

  // Check timestamp freshness
  const age = Date.now() - payload.timestamp;
  if (age < 0 || age > config.authTimestampTtlMs) {
    throw new AuthError(401, 'auth timestamp expired or invalid', 'auth-expired');
  }

  if (!signature || typeof signature !== 'string') {
    throw new AuthError(401, 'signature is required', 'missing-signature');
  }

  // Verify SIP-018 signature via StackFlow node
  // The signed message is the canonical JSON of the payload
  const message = JSON.stringify(payload);

  try {
    const res = await fetch(`${stackflowNodeUrl}/sip018/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: payload.address, message, signature }),
      signal: AbortSignal.timeout(5_000),
    });

    if (!res.ok) {
      throw new AuthError(401, 'signature verification failed', 'invalid-signature');
    }

    const body = await res.json() as Record<string, unknown>;
    if (!body['valid']) {
      throw new AuthError(401, 'signature verification failed', 'invalid-signature');
    }
  } catch (err) {
    if (err instanceof AuthError) throw err;
    throw new AuthError(503, 'could not verify signature', 'auth-service-unavailable');
  }

  return payload;
}
