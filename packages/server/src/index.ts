// Stackmail server — entry point

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

import { loadConfig } from './types.js';
import { SqliteMessageStore } from './store.js';
import { PaymentService, PaymentError } from './payment.js';
import { verifyInboxAuth, AuthError } from './auth.js';

const config = loadConfig();
const store = new SqliteMessageStore(config.dbFile);
const paymentService = new PaymentService(config);

async function main(): Promise<void> {
  await mkdir(dirname(config.dbFile), { recursive: true });
  await store.init();

  const server = createServer(handleRequest);
  server.listen(config.port, config.host, () => {
    console.log(`stackmail server listening on ${config.host}:${config.port}`);
  });
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  const method = req.method?.toUpperCase() ?? 'GET';
  const path = url.pathname;

  try {
    // GET /health
    if (method === 'GET' && path === '/health') {
      return json(res, 200, { ok: true });
    }

    // GET /payment-info/{addr}
    const paymentInfoMatch = path.match(/^\/payment-info\/([^/]+)$/);
    if (method === 'GET' && paymentInfoMatch) {
      const recipientAddr = decodeURIComponent(paymentInfoMatch[1]);
      const { public: info, internal } = paymentService.generatePaymentInfo(recipientAddr);
      await store.savePendingPaymentInfo({
        paymentId: internal.paymentId,
        hashedSecret: internal.hashedSecret,
        recipientAddr: internal.recipientAddr,
        amount: internal.amount,
        fee: internal.fee,
        expiresAt: internal.expiresAt,
      });
      return json(res, 200, info);
    }

    // POST /messages/{addr}
    const sendMatch = path.match(/^\/messages\/([^/]+)$/);
    if (method === 'POST' && sendMatch) {
      const recipientAddr = decodeURIComponent(sendMatch[1]);
      return await handleSend(req, res, recipientAddr);
    }

    // GET /inbox
    if (method === 'GET' && path === '/inbox') {
      return await handleGetInbox(req, res, url);
    }

    // POST /inbox/{id}/claim
    const claimMatch = path.match(/^\/inbox\/([^/]+)\/claim$/);
    if (method === 'POST' && claimMatch) {
      const msgId = decodeURIComponent(claimMatch[1]);
      return await handleClaim(req, res, msgId);
    }

    // GET /inbox/{id}
    const getMessageMatch = path.match(/^\/inbox\/([^/]+)$/);
    if (method === 'GET' && getMessageMatch) {
      const msgId = decodeURIComponent(getMessageMatch[1]);
      return await handleGetMessage(req, res, msgId);
    }

    return json(res, 404, { error: 'not-found' });
  } catch (err) {
    console.error('unhandled error', err);
    return json(res, 500, { error: 'internal-error' });
  }
}

async function handleSend(req: IncomingMessage, res: ServerResponse, to: string): Promise<void> {
  // Parse x402 payment proof from header
  const paymentHeader = req.headers['x-x402-payment'] ?? req.headers['x-stackmail-payment'];
  if (!paymentHeader) {
    return json(res, 402, {
      error: 'payment-required',
      accepts: [{ mode: 'indirect', description: 'StackFlow indirect payment' }],
      stackflowNodeUrl: config.stackflowNodeUrl,
      serverAddress: config.serverStxAddress,
    });
  }

  let proof: unknown;
  try {
    const raw = Array.isArray(paymentHeader) ? paymentHeader[0] : paymentHeader;
    proof = JSON.parse(Buffer.from(raw, 'base64url').toString('utf-8'));
  } catch {
    try {
      const raw = Array.isArray(paymentHeader) ? paymentHeader[0] : paymentHeader;
      proof = JSON.parse(raw);
    } catch {
      return json(res, 400, { error: 'invalid-payment-header' });
    }
  }

  let paymentResult: { paymentId: string; amount: string };
  try {
    paymentResult = await paymentService.verifyIncomingPayment(proof);
  } catch (err) {
    if (err instanceof PaymentError) {
      return json(res, err.statusCode, { error: err.reason, message: err.message });
    }
    throw err;
  }

  // Parse message body
  const body = await readBody(req, config.maxBodyBytes);
  let msgData: { subject?: string; body: string; from: string };
  try {
    msgData = JSON.parse(body) as typeof msgData;
  } catch {
    return json(res, 400, { error: 'invalid-body', message: 'body must be JSON' });
  }

  if (!msgData.from || typeof msgData.from !== 'string') {
    return json(res, 400, { error: 'from-required' });
  }
  if (!msgData.body || typeof msgData.body !== 'string') {
    return json(res, 400, { error: 'body-required' });
  }
  if (Buffer.byteLength(msgData.body, 'utf-8') > config.maxBodyBytes) {
    return json(res, 413, { error: 'body-too-large' });
  }
  if (msgData.subject && msgData.subject.length > config.maxSubjectLength) {
    return json(res, 400, { error: 'subject-too-long' });
  }

  // Look up payment info to get fee/recipientAmount
  const paymentInfo = await store.getPendingPaymentInfo(paymentResult.paymentId);
  const fee = paymentInfo?.fee ?? config.minFeeSats;

  await store.savePendingMessage({
    id: randomUUID(),
    from: msgData.from,
    to,
    subject: msgData.subject,
    body: msgData.body,
    sentAt: Date.now(),
    amount: paymentResult.amount,
    fee,
    paymentId: paymentResult.paymentId,
    hashedSecret: '',   // filled from paymentInfo if available
    claimed: false,
  });

  return json(res, 200, { ok: true, messageId: paymentResult.paymentId });
}

async function handleGetInbox(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const authHeader = req.headers['x-stackmail-auth'];
  if (!authHeader) {
    return json(res, 401, { error: 'auth-required' });
  }

  let payload;
  try {
    payload = await verifyInboxAuth(
      Array.isArray(authHeader) ? authHeader[0] : authHeader,
      config.stackflowNodeUrl,
      config,
    );
  } catch (err) {
    if (err instanceof AuthError) {
      return json(res, err.statusCode, { error: err.reason, message: err.message });
    }
    throw err;
  }

  const limit = parseInt(url.searchParams.get('limit') ?? '50', 10);
  const before = url.searchParams.get('before') ? parseInt(url.searchParams.get('before')!, 10) : undefined;
  const includeClaimed = url.searchParams.get('claimed') === 'true';

  const entries = await store.getInbox(payload.address, { limit, before, includeClained: includeClaimed });
  return json(res, 200, { messages: entries });
}

async function handleClaim(req: IncomingMessage, res: ServerResponse, msgId: string): Promise<void> {
  const authHeader = req.headers['x-stackmail-auth'];
  if (!authHeader) {
    return json(res, 401, { error: 'auth-required' });
  }

  let payload;
  try {
    payload = await verifyInboxAuth(
      Array.isArray(authHeader) ? authHeader[0] : authHeader,
      config.stackflowNodeUrl,
      config,
    );
  } catch (err) {
    if (err instanceof AuthError) {
      return json(res, err.statusCode, { error: err.reason, message: err.message });
    }
    throw err;
  }

  let message;
  try {
    message = await store.claimMessage(msgId, payload.address);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg === 'message-not-found') return json(res, 404, { error: 'not-found' });
    if (msg === 'already-claimed') return json(res, 409, { error: 'already-claimed' });
    throw err;
  }

  // Reveal secret to StackFlow node so recipient's channel gets credited
  let secret: string | null = null;
  try {
    secret = await paymentService.revealSecretForPayment(message.paymentId);
    await store.markPaymentSettled(message.paymentId);
  } catch (err) {
    // Log but don't block message delivery — payment settling can retry
    console.error('payment reveal failed', message.paymentId, err);
  }

  return json(res, 200, { message, secret });
}

async function handleGetMessage(req: IncomingMessage, res: ServerResponse, msgId: string): Promise<void> {
  const authHeader = req.headers['x-stackmail-auth'];
  if (!authHeader) {
    return json(res, 401, { error: 'auth-required' });
  }

  let payload;
  try {
    payload = await verifyInboxAuth(
      Array.isArray(authHeader) ? authHeader[0] : authHeader,
      config.stackflowNodeUrl,
      config,
    );
  } catch (err) {
    if (err instanceof AuthError) {
      return json(res, err.statusCode, { error: err.reason, message: err.message });
    }
    throw err;
  }

  const message = await store.getClaimedMessage(msgId, payload.address);
  if (!message) return json(res, 404, { error: 'not-found' });
  return json(res, 200, { message });
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) });
  res.end(data);
}

async function readBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('body-too-large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

main().catch(err => {
  console.error('fatal:', err);
  process.exit(1);
});
