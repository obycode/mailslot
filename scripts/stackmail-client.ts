/**
 * Stackmail TypeScript Client SDK
 *
 * Standalone client for the Stackmail mainnet deployment.
 * Copy this file into your project; it has no external deps beyond @noble/curves.
 *
 * ─── Mainnet Deployment ────────────────────────────────────────────────────────
 *
 * Deployer: SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR
 *   sm-test-token  – TEST SIP-010 token
 *   sm-stackflow   – StackFlow v0.6.0 payment channels
 *   sm-reservoir   – reservoir hub
 *
 * Server: SP1RCWQSAF1Q96CPX77Q9EAR236N19P09T6E2KDRE
 * URL:    http://127.0.0.1:8800
 *
 * ─── Quick Start ───────────────────────────────────────────────────────────────
 *
 *   // Create or load your keypair
 *   const kp = genKeypair();           // new keypair
 *   // const kp = keypairFromPrivkey("your_priv_key_hex");
 *
 *   // Register your mailbox (one-time, receives your pubkey)
 *   await registerMailbox(kp.privHex);
 *
 *   // Send a message (requires a funded pipe state)
 *   const { messageId, newPipeState } = await sendMessage({
 *     to: recipientAddr,
 *     subject: 'Hello',
 *     body: 'World',
 *     privkeyHex: kp.privHex,
 *     pipeState: { serverBalance: 0n, myBalance: 100_000n, nonce: 0n },
 *   });
 *
 *   // Check and claim new messages
 *   const messages = await readNewMessages(kp.privHex);
 *   console.log(messages[0].body);
 */

import { createHash, randomBytes, createECDH, createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';

// ─── Constants ────────────────────────────────────────────────────────────────

export const DEFAULTS = {
  SERVER_URL:    'http://127.0.0.1:8800',
  /** The reservoir contract IS the server's on-chain identity. Taps are opened to this address. */
  RESERVOIR:     'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir',
  SF_CONTRACT:   'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow',
  TOKEN:         'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token',
  CHAIN_ID:      1,
  MESSAGE_PRICE: 1000n,
} as const;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Keypair {
  privHex: string;
  pubHex: string;
  addr: string;
}

export interface PipeState {
  serverBalance: bigint;
  myBalance: bigint;
  nonce: bigint;
}

export interface InboxEntry {
  id: string;
  from: string;
  sentAt: number;
  amount: string;
  claimed: boolean;
}

export interface DecryptedMessage {
  id: string;
  from: string;
  sentAt: number;
  amount: string;
  subject?: string;
  body: string;
  secret: string;
}

export interface EncryptedMail {
  v: 1;
  epk: string;   // 33 bytes compressed pubkey hex
  iv: string;    // 12 bytes hex
  data: string;  // AES-256-GCM ciphertext + auth_tag hex
}

export interface MailPayload {
  v: 1;
  secret: string;   // 32 bytes hex HTLC preimage
  subject?: string;
  body: string;
}

// ─── c32 Address Helpers ──────────────────────────────────────────────────────

const C32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function c32encode(data: Buffer): string {
  let n = BigInt('0x' + data.toString('hex'));
  const chars: string[] = [];
  while (n > 0n) { chars.push(C32[Number(n % 32n)]); n /= 32n; }
  for (const b of data) { if (b === 0) chars.push('0'); else break; }
  return chars.reverse().join('');
}

/** Decode a c32-encoded string to a fixed-size byte array. */
function c32DecodeFixed(encoded: string, expectedBytes: number): Buffer {
  const result = Buffer.alloc(expectedBytes, 0);
  let carry = 0, carryBits = 0, byteIdx = expectedBytes - 1;
  for (let i = encoded.length - 1; i >= 0 && byteIdx >= 0; i--) {
    const val = C32.indexOf(encoded[i].toUpperCase());
    if (val < 0) throw new Error(`Invalid c32 char: ${encoded[i]}`);
    carry |= (val << carryBits);
    carryBits += 5;
    if (carryBits >= 8) { result[byteIdx--] = carry & 0xff; carry >>= 8; carryBits -= 8; }
  }
  return result;
}

function parseStxAddress(address: string): { version: number; hash160: Buffer } {
  const addr = address.includes('.') ? address.slice(0, address.indexOf('.')) : address;
  if (addr[0] !== 'S') throw new Error(`Invalid STX address: ${addr}`);
  const version = C32.indexOf(addr[1].toUpperCase());
  const decoded = c32DecodeFixed(addr.slice(2), 24);
  return { version, hash160: decoded.subarray(0, 20) };
}

/** Derive STX mainnet address from compressed secp256k1 pubkey (33 bytes hex). */
export function pubkeyToStxAddress(pubkeyHex: string): string {
  const pub = Buffer.from(pubkeyHex, 'hex');
  const sha = createHash('sha256').update(pub).digest();
  const h160 = createHash('ripemd160').update(sha).digest();
  const version = 22;
  const payload = Buffer.concat([Buffer.from([version]), h160]);
  const h1 = createHash('sha256').update(payload).digest();
  const checksum = createHash('sha256').update(h1).digest().subarray(0, 4);
  return 'S' + C32[version] + c32encode(Buffer.concat([h160, checksum]));
}

/** Create a new random keypair. Keep privHex secret. */
export function genKeypair(): Keypair {
  const priv = randomBytes(32);
  const pub = secp256k1.getPublicKey(priv, true);
  const privHex = Buffer.from(priv).toString('hex');
  const pubHex = Buffer.from(pub).toString('hex');
  return { privHex, pubHex, addr: pubkeyToStxAddress(pubHex) };
}

/** Derive keypair from an existing private key hex string. */
export function keypairFromPrivkey(privHex: string): Keypair {
  const pub = secp256k1.getPublicKey(Buffer.from(privHex, 'hex'), true);
  const pubHex = Buffer.from(pub).toString('hex');
  return { privHex, pubHex, addr: pubkeyToStxAddress(pubHex) };
}

// ─── Canonical pipe key ───────────────────────────────────────────────────────

/**
 * Compute the Clarity consensus-buff representation of a principal.
 * Standard:  0x05 <version> <hash160>                      (22 bytes)
 * Contract:  0x06 <version> <hash160> <name_len> <name>    (22 + 1 + n bytes)
 *
 * Since 0x05 < 0x06, a standard address is always "less than" a contract principal,
 * meaning in a Stackmail tap the agent (standard) is always principal-1 and the
 * reservoir (contract) is always principal-2.
 */
function toConsensusBuff(addr: string): Buffer {
  const dotIdx = addr.indexOf('.');
  if (dotIdx < 0) {
    const { version, hash160 } = parseStxAddress(addr);
    return Buffer.concat([Buffer.from([0x05, version]), hash160]);
  } else {
    const { version, hash160 } = parseStxAddress(addr.slice(0, dotIdx));
    const nameBytes = Buffer.from(addr.slice(dotIdx + 1), 'ascii');
    return Buffer.concat([Buffer.from([0x06, version]), hash160, Buffer.from([nameBytes.length]), nameBytes]);
  }
}

function canonicalPipeKey(token: string, addr1: string, addr2: string) {
  const p1 = toConsensusBuff(addr1);
  const p2 = toConsensusBuff(addr2);
  return Buffer.compare(p1, p2) < 0
    ? { token, 'principal-1': addr1, 'principal-2': addr2 }
    : { token, 'principal-1': addr2, 'principal-2': addr1 };
}

// ─── Clarity serialization (for SIP-018) ──────────────────────────────────────
// Matches the consensus-buff encoding used by the StackFlow contract.

type ClarityValue =
  | { type: 'uint';         value: bigint | string | number }
  | { type: 'principal';    value: string }
  | { type: 'buff';         value: string }  // hex, optional 0x prefix
  | { type: 'none' }
  | { type: 'some';         value: ClarityValue }
  | { type: 'string-ascii'; value: string }
  | { type: 'tuple';        fields: Record<string, ClarityValue> };

function u32be(n: number): Buffer {
  const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b;
}

function u128be(n: bigint): Buffer {
  const b = Buffer.alloc(16, 0);
  let v = BigInt.asUintN(128, n);
  for (let i = 15; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}

function serializePrincipal(value: string): Buffer {
  const dotIdx = value.indexOf('.');
  if (dotIdx < 0) {
    const { version, hash160 } = parseStxAddress(value);
    return Buffer.concat([Buffer.from([0x05, version]), hash160]);
  }
  const { version, hash160 } = parseStxAddress(value.slice(0, dotIdx));
  const nameBytes = Buffer.from(value.slice(dotIdx + 1), 'ascii');
  return Buffer.concat([Buffer.from([0x06, version]), hash160, Buffer.from([nameBytes.length]), nameBytes]);
}

function serializeClarityValue(cv: ClarityValue): Buffer {
  switch (cv.type) {
    case 'uint': {
      const n = typeof cv.value === 'bigint' ? cv.value : BigInt(String(cv.value));
      return Buffer.concat([Buffer.from([0x01]), u128be(n)]);
    }
    case 'principal': return serializePrincipal(cv.value);
    case 'buff': {
      const bytes = Buffer.from((cv.value as string).replace(/^0x/, ''), 'hex');
      return Buffer.concat([Buffer.from([0x02]), u32be(bytes.length), bytes]);
    }
    case 'none':  return Buffer.from([0x09]);
    case 'some':  return Buffer.concat([Buffer.from([0x0a]), serializeClarityValue(cv.value)]);
    case 'string-ascii': {
      const bytes = Buffer.from(cv.value as string, 'ascii');
      return Buffer.concat([Buffer.from([0x0d]), u32be(bytes.length), bytes]);
    }
    case 'tuple': {
      const names = Object.keys(cv.fields).sort();
      const parts: Buffer[] = [Buffer.from([0x0c]), u32be(names.length)];
      for (const name of names) {
        const nb = Buffer.from(name, 'utf-8');
        parts.push(Buffer.from([nb.length]), nb, serializeClarityValue(cv.fields[name]));
      }
      return Buffer.concat(parts);
    }
  }
}

// ─── SIP-018 signing ──────────────────────────────────────────────────────────

const SIP018_PREFIX = Buffer.from('534950303138', 'hex'); // "SIP018"

function sha256(data: Buffer | string): Buffer {
  return createHash('sha256').update(data as Buffer).digest();
}

function buildSip018Domain(contractId: string, chainId: number): ClarityValue {
  return {
    type: 'tuple',
    fields: {
      'chain-id': { type: 'uint', value: BigInt(chainId) },
      name:       { type: 'string-ascii', value: contractId },
      version:    { type: 'string-ascii', value: '0.6.0' },
    },
  };
}

/** Build the SIP-018 TypedMessage for a StackFlow transfer state update. */
function buildTransferMessage(state: {
  pipeKey: { token: string; 'principal-1': string; 'principal-2': string };
  forPrincipal: string;
  myBalance: string;
  theirBalance: string;
  nonce: string;
  action: string;
  actor: string;
  hashedSecret: string | null;
  validAfter: string | null;
}): Record<string, ClarityValue> {
  const isP1 = state.pipeKey['principal-1'] === state.forPrincipal;
  const balance1 = isP1 ? state.myBalance : state.theirBalance;
  const balance2 = isP1 ? state.theirBalance : state.myBalance;
  return {
    'principal-1': { type: 'principal', value: state.pipeKey['principal-1'] },
    'principal-2': { type: 'principal', value: state.pipeKey['principal-2'] },
    token: state.pipeKey.token == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'principal', value: state.pipeKey.token } },
    'balance-1': { type: 'uint', value: balance1 },
    'balance-2': { type: 'uint', value: balance2 },
    nonce:       { type: 'uint', value: state.nonce },
    action:      { type: 'uint', value: state.action },
    actor:       { type: 'principal', value: state.actor },
    'hashed-secret': state.hashedSecret == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'buff', value: state.hashedSecret } },
    'valid-after': state.validAfter == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'uint', value: state.validAfter } },
  };
}

function computeSip018Hash(
  contractId: string,
  message: Record<string, ClarityValue>,
  chainId: number,
): Buffer {
  const domainHash = sha256(serializeClarityValue(buildSip018Domain(contractId, chainId)));
  const messageHash = sha256(serializeClarityValue({ type: 'tuple', fields: message }));
  return sha256(Buffer.concat([SIP018_PREFIX, domainHash, messageHash]));
}

/** Sign a SIP-018 StackFlow state update. Returns 65-byte hex: "0x" + recovery + r + s. */
async function sip018Sign(
  contractId: string,
  message: Record<string, ClarityValue>,
  privkeyHex: string,
  chainId: number,
): Promise<string> {
  const hash = computeSip018Hash(contractId, message, chainId);
  const sig = secp256k1.sign(hash, Buffer.from(privkeyHex, 'hex'), { lowS: true });
  const full = Buffer.concat([Buffer.from([sig.recovery ?? 0]), Buffer.from(sig.toCompactRawBytes())]);
  return '0x' + full.toString('hex');
}

// ─── ECIES Encryption ─────────────────────────────────────────────────────────

const HKDF_SALT = Buffer.from('stackmail-v1', 'utf-8');
const HKDF_INFO = Buffer.from('encrypt', 'utf-8');

function deriveKey(sharedSecret: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', sharedSecret, HKDF_SALT, HKDF_INFO, 32));
}

/** Encrypt a MailPayload for a recipient's compressed secp256k1 pubkey. */
export function encryptMail(payload: MailPayload, recipientPubkeyHex: string): EncryptedMail {
  const recipientPubkey = Buffer.from(recipientPubkeyHex, 'hex');
  const ecdh = createECDH('secp256k1');
  ecdh.generateKeys();
  const epk = ecdh.getPublicKey(undefined, 'compressed') as Buffer;
  const sharedSecret = ecdh.computeSecret(recipientPubkey);
  const key = deriveKey(sharedSecret);
  const iv = randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf-8');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    v: 1,
    epk: epk.toString('hex'),
    iv: iv.toString('hex'),
    data: Buffer.concat([ciphertext, authTag]).toString('hex'),
  };
}

/** Decrypt an EncryptedMail using the recipient's secp256k1 private key (32 bytes hex). */
export function decryptMail(encrypted: EncryptedMail, privkeyHex: string): MailPayload {
  const privkey = Buffer.from(privkeyHex, 'hex');
  const epk = Buffer.from(encrypted.epk, 'hex');
  const iv = Buffer.from(encrypted.iv, 'hex');
  const combined = Buffer.from(encrypted.data, 'hex');
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(privkey);
  const sharedSecret = ecdh.computeSecret(epk);
  const key = deriveKey(sharedSecret);
  const ciphertext = combined.subarray(0, combined.length - 16);
  const authTag = combined.subarray(combined.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf-8')) as MailPayload;
}

/** Compute the HTLC hash: SHA-256 of the secret bytes. */
export function hashSecret(secretHex: string): string {
  return createHash('sha256').update(Buffer.from(secretHex, 'hex')).digest('hex');
}

// ─── Auth header ──────────────────────────────────────────────────────────────

function buildAuthHeader(
  privHex: string,
  pubHex: string,
  addr: string,
  action: 'get-inbox' | 'get-message' | 'claim-message',
  messageId?: string,
): string {
  const payload = { action, address: addr, timestamp: Date.now(), ...(messageId ? { messageId } : {}) };
  const hash = sha256(Buffer.from(JSON.stringify(payload)));
  const sig = secp256k1.sign(hash, Buffer.from(privHex, 'hex'), { lowS: true });
  const sigHex = Buffer.from(sig.toCompactRawBytes()).toString('hex');
  return Buffer.from(JSON.stringify({ pubkey: pubHex, payload, signature: sigHex })).toString('base64');
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

async function http(
  method: string,
  url: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; ok: boolean; data: unknown }> {
  const opts: RequestInit = { method, headers: { ...headers } };
  if (body !== undefined) {
    (opts.headers as Record<string, string>)['content-type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(url, opts);
  const text = await r.text();
  let data: unknown;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, ok: r.ok, data };
}

// ─── Public Client API ────────────────────────────────────────────────────────

/**
 * Register your mailbox with the server (one-time).
 *
 * Authenticates with the server, which stores your pubkey so senders can
 * look you up via GET /payment-info/:addr.
 *
 * Must be called before you can receive messages.
 */
export async function registerMailbox(
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<{ address: string }> {
  const kp = keypairFromPrivkey(privkeyHex);
  const authHeader = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox');
  const r = await http('GET', `${serverUrl}/inbox`, undefined, { 'x-stackmail-auth': authHeader });
  if (r.status !== 200 && r.status !== 404) {
    throw new Error(`registerMailbox failed: ${r.status} ${JSON.stringify(r.data)}`);
  }
  console.log(`Mailbox registered: ${kp.addr}`);
  return { address: kp.addr };
}

/**
 * Get payment info for a recipient address.
 *
 * Returns their public key and the message price.
 * The recipient must have called registerMailbox() first.
 */
export async function getPaymentInfo(
  recipientAddr: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<{ recipientPublicKey: string; amount: string; serverAddress: string }> {
  const r = await http('GET', `${serverUrl}/payment-info/${recipientAddr}`);
  if (!r.ok) throw new Error(`getPaymentInfo failed: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data as { recipientPublicKey: string; amount: string; serverAddress: string };
}

/**
 * Send a message to a recipient.
 *
 * Builds a SIP-018 payment proof and sends the ECIES-encrypted message.
 *
 * @param to           Recipient's STX address
 * @param subject      Message subject line
 * @param body         Message body text
 * @param privkeyHex   Your secp256k1 private key (32 bytes hex)
 * @param pipeState    Current state of your payment channel to the server
 *                     { serverBalance, myBalance, nonce }
 *                     For a fresh channel: { serverBalance: 0n, myBalance: <funded_amount>, nonce: 0n }
 * @param serverUrl    Mailbox server URL
 *
 * @returns messageId and the updated pipeState after the payment
 */
export async function sendMessage({
  to,
  subject,
  body,
  privkeyHex,
  pipeState,
  serverUrl = DEFAULTS.SERVER_URL,
  sfContract = DEFAULTS.SF_CONTRACT,
  token = DEFAULTS.TOKEN,
  chainId = DEFAULTS.CHAIN_ID,
  messagePrice = DEFAULTS.MESSAGE_PRICE,
}: {
  to: string;
  subject: string;
  body: string;
  privkeyHex: string;
  pipeState: PipeState;
  serverUrl?: string;
  sfContract?: string;
  token?: string;
  chainId?: number;
  messagePrice?: bigint;
}): Promise<{ messageId: string; newPipeState: PipeState }> {
  const kp = keypairFromPrivkey(privkeyHex);
  const serverAddr = DEFAULTS.RESERVOIR;  // pipe counterparty is the reservoir contract

  if (pipeState.myBalance < messagePrice) {
    throw new Error(`Insufficient channel balance: have ${pipeState.myBalance}, need ${messagePrice}`);
  }

  // 1. Look up recipient's public key
  const payInfo = await getPaymentInfo(to, serverUrl);

  // 2. Generate HTLC secret and encrypt message body
  const secretHex = randomBytes(32).toString('hex');
  const hashedSecretHex = hashSecret(secretHex);
  const encPayload = encryptMail({ v: 1, secret: secretHex, subject, body }, payInfo.recipientPublicKey);

  // 3. Compute new channel balances
  const newServerBalance = pipeState.serverBalance + messagePrice;
  const newMyBalance     = pipeState.myBalance - messagePrice;
  const nextNonce        = pipeState.nonce + 1n;
  const pipeKey          = canonicalPipeKey(token, kp.addr, serverAddr);

  // 4. Build and sign the state update (from sender's perspective)
  const state = {
    pipeKey,
    forPrincipal: kp.addr,
    myBalance: newMyBalance.toString(),
    theirBalance: newServerBalance.toString(),
    nonce: nextNonce.toString(),
    action: '1',
    actor: kp.addr,
    hashedSecret: hashedSecretHex,
    validAfter: null,
  };
  const message = buildTransferMessage(state);
  const sig = await sip018Sign(sfContract, message, privkeyHex, chainId);

  // 5. Encode payment proof (from server's perspective)
  const proof = {
    contractId: sfContract,
    pipeKey,
    forPrincipal: serverAddr,
    withPrincipal: kp.addr,
    myBalance: newServerBalance.toString(),
    theirBalance: newMyBalance.toString(),
    nonce: nextNonce.toString(),
    action: '1',
    actor: kp.addr,
    hashedSecret: hashedSecretHex,
    theirSignature: sig,
    validAfter: null,
  };
  const proofHeader = Buffer.from(JSON.stringify(proof)).toString('base64url');

  // 6. Send
  const r = await http(
    'POST',
    `${serverUrl}/messages/${to}`,
    { from: kp.addr, encryptedPayload: encPayload },
    { 'x-stackmail-payment': proofHeader },
  );
  if (!r.ok) throw new Error(`sendMessage failed: ${r.status} ${JSON.stringify(r.data)}`);

  return {
    messageId: (r.data as { messageId: string }).messageId,
    newPipeState: { serverBalance: newServerBalance, myBalance: newMyBalance, nonce: nextNonce },
  };
}

/**
 * Get your inbox (message headers, no content).
 *
 * @param privkeyHex      Your private key (32 bytes hex)
 * @param serverUrl       Mailbox server URL
 * @param includeClaimed  Include already-claimed messages (default: false)
 */
export async function getInbox(
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
  includeClaimed = false,
): Promise<InboxEntry[]> {
  const kp = keypairFromPrivkey(privkeyHex);
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox');
  const url = `${serverUrl}/inbox${includeClaimed ? '?claimed=true' : ''}`;
  const r = await http('GET', url, undefined, { 'x-stackmail-auth': auth });
  if (!r.ok) throw new Error(`getInbox failed: ${r.status} ${JSON.stringify(r.data)}`);
  return ((r.data as { messages: InboxEntry[] }).messages) ?? [];
}

/**
 * Preview a message: fetch the encrypted envelope without decrypting.
 * The encrypted payload contains subject, body, AND the HTLC secret.
 */
export async function previewMessage(
  messageId: string,
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<{ from: string; sentAt: number; amount: string; encryptedPayload: EncryptedMail; hashedSecret: string }> {
  const kp = keypairFromPrivkey(privkeyHex);
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-message', messageId);
  const r = await http('GET', `${serverUrl}/inbox/${messageId}/preview`, undefined, { 'x-stackmail-auth': auth });
  if (!r.ok) throw new Error(`previewMessage failed: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data as Awaited<ReturnType<typeof previewMessage>>;
}

/**
 * Claim a message by revealing the HTLC preimage.
 *
 * This decrypts the message payload (getting the secret), verifies the HTLC
 * hash matches, and claims it from the server to unlock your payment.
 *
 * After claiming, the server forwards payment to you via the outgoing channel.
 *
 * @param messageId   Message ID to claim
 * @param privkeyHex  Your private key (used for auth and decryption)
 * @param serverUrl   Mailbox server URL
 */
export async function claimMessage(
  messageId: string,
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<DecryptedMessage> {
  const kp = keypairFromPrivkey(privkeyHex);

  // Get encrypted payload
  const preview = await previewMessage(messageId, privkeyHex, serverUrl);

  // Decrypt to get the HTLC secret + message content
  const decrypted = decryptMail(preview.encryptedPayload, kp.privHex);

  // Verify the secret matches the payment commitment
  const computedHash = hashSecret(decrypted.secret);
  const expectedHash = preview.hashedSecret.startsWith('0x')
    ? preview.hashedSecret.slice(2)
    : preview.hashedSecret;
  if (computedHash !== expectedHash) {
    throw new Error('Secret hash mismatch — message may be corrupted');
  }

  // Reveal the secret to claim the payment
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'claim-message', messageId);
  const r = await http(
    'POST',
    `${serverUrl}/inbox/${messageId}/claim`,
    { secret: decrypted.secret },
    { 'x-stackmail-auth': auth },
  );
  if (!r.ok) throw new Error(`claimMessage failed: ${r.status} ${JSON.stringify(r.data)}`);

  return {
    id: messageId,
    from: preview.from,
    sentAt: preview.sentAt,
    amount: preview.amount,
    subject: decrypted.subject,
    body: decrypted.body,
    secret: decrypted.secret,
  };
}

/**
 * Read and claim all new (unclaimed) messages in your inbox.
 * Returns fully decrypted messages.
 */
export async function readNewMessages(
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<DecryptedMessage[]> {
  const inbox = await getInbox(privkeyHex, serverUrl, false);
  const unclaimed = inbox.filter(m => !m.claimed);
  const results: DecryptedMessage[] = [];
  for (const entry of unclaimed) {
    try {
      results.push(await claimMessage(entry.id, privkeyHex, serverUrl));
    } catch (e) {
      console.error(`Failed to claim ${entry.id}:`, e);
    }
  }
  return results;
}
