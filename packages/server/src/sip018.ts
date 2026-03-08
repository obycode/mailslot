/**
 * SIP-018 structured data hashing and signing for StackFlow transfers.
 *
 * Algorithm:
 *   domain = { chain-id: uint, name: string-ascii, version: string-ascii }
 *   message = { action, actor, balance-1, balance-2, hashed-secret, nonce, principal-1, principal-2, token, valid-after }
 *   hash = sha256("SIP018" || sha256(clarity_serialize(domain)) || sha256(clarity_serialize(message)))
 *
 * Signatures are 65 bytes: [recovery_id (0|1), r (32 bytes), s (32 bytes)]
 */

import { createHash } from 'node:crypto';

// ─── Clarity value types ──────────────────────────────────────────────────────

export type ClarityValue =
  | { type: 'uint'; value: number | bigint | string }
  | { type: 'principal'; value: string }
  | { type: 'buff'; value: string }         // hex string, optional 0x prefix
  | { type: 'none' }
  | { type: 'some'; value: ClarityValue }
  | { type: 'string-ascii'; value: string }
  | { type: 'tuple'; fields: Record<string, ClarityValue> };

/** Typed message object as used in agent-service.js */
export type TypedField = { type: string; value?: unknown };
export type TypedMessage = Record<string, TypedField>;

// ─── c32 address decoding ─────────────────────────────────────────────────────

const C32_CHARS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * Decode a c32-encoded string to fixed-size byte array.
 * Uses the reverse of the c32encode algorithm: processes chars right-to-left,
 * accumulates bits, outputs bytes right-to-left.
 */
function c32DecodeFixed(encoded: string, expectedBytes: number): Buffer {
  const result = Buffer.alloc(expectedBytes, 0);
  let carry = 0;
  let carryBits = 0;
  let byteIdx = expectedBytes - 1;

  for (let i = encoded.length - 1; i >= 0 && byteIdx >= 0; i--) {
    const ch = encoded[i].toUpperCase();
    const val = C32_CHARS.indexOf(ch);
    if (val < 0) throw new Error(`Invalid c32 character: ${ch}`);
    carry |= (val << carryBits);
    carryBits += 5;
    if (carryBits >= 8) {
      result[byteIdx--] = carry & 0xff;
      carry >>= 8;
      carryBits -= 8;
    }
  }

  return result;
}

/** Parse "SP..." or "ST..." address to (version, hash160). Also accepts "SP...addr.contract". */
export function parseStxAddress(address: string): { version: number; hash160: Buffer } {
  const dotIdx = address.indexOf('.');
  const addr = dotIdx >= 0 ? address.slice(0, dotIdx) : address;
  if (addr.length < 3 || addr[0] !== 'S') throw new Error(`Invalid STX address: ${addr}`);
  const version = C32_CHARS.indexOf(addr[1].toUpperCase());
  if (version < 0) throw new Error(`Invalid STX address version: ${addr[1]}`);
  // 24 bytes = 20-byte hash160 + 4-byte checksum
  const decoded = c32DecodeFixed(addr.slice(2), 24);
  return { version, hash160: decoded.subarray(0, 20) };
}

// ─── Clarity serialization ────────────────────────────────────────────────────

function u32be(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n, 0);
  return b;
}

function u128be(n: bigint): Buffer {
  const b = Buffer.alloc(16, 0);
  let v = BigInt.asUintN(128, n);
  for (let i = 15; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
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
  return Buffer.concat([
    Buffer.from([0x06, version]),
    hash160,
    Buffer.from([nameBytes.length]),
    nameBytes,
  ]);
}

/** Serialize a Clarity value to its consensus-buff representation. Tuples are field-sorted. */
export function serializeClarityValue(cv: ClarityValue): Buffer {
  switch (cv.type) {
    case 'uint': {
      const n = typeof cv.value === 'bigint' ? cv.value : BigInt(String(cv.value));
      return Buffer.concat([Buffer.from([0x01]), u128be(n)]);
    }
    case 'principal':
      return serializePrincipal(cv.value);
    case 'buff': {
      const bytes = Buffer.from(cv.value.replace(/^0x/, ''), 'hex');
      return Buffer.concat([Buffer.from([0x02]), u32be(bytes.length), bytes]);
    }
    case 'none':
      return Buffer.from([0x09]);
    case 'some':
      return Buffer.concat([Buffer.from([0x0a]), serializeClarityValue(cv.value)]);
    case 'string-ascii': {
      const bytes = Buffer.from(cv.value, 'ascii');
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

// ─── SIP-018 hash ─────────────────────────────────────────────────────────────

const SIP018_PREFIX = Buffer.from('534950303138', 'hex'); // "SIP018"
const SF_VERSION = '0.6.0';

function sha256(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

function buildDomain(contractId: string, chainId: number): ClarityValue {
  return {
    type: 'tuple',
    fields: {
      'chain-id': { type: 'uint', value: BigInt(chainId) },
      name: { type: 'string-ascii', value: contractId },
      version: { type: 'string-ascii', value: SF_VERSION },
    },
  };
}

function convertTypedField(v: TypedField): ClarityValue {
  switch (v.type) {
    case 'uint': return { type: 'uint', value: BigInt(String(v.value)) };
    case 'principal': return { type: 'principal', value: v.value as string };
    case 'buff': return { type: 'buff', value: v.value as string };
    case 'none': return { type: 'none' };
    case 'some': return { type: 'some', value: convertTypedField(v.value as TypedField) };
    case 'string-ascii': return { type: 'string-ascii', value: v.value as string };
    default: throw new Error(`Unknown typed field: ${v.type}`);
  }
}

function buildMessageTuple(msg: TypedMessage): ClarityValue {
  const fields: Record<string, ClarityValue> = {};
  for (const [k, v] of Object.entries(msg)) fields[k] = convertTypedField(v);
  return { type: 'tuple', fields };
}

/** Compute the SIP-018 hash for a StackFlow transfer message. */
export function computeSip018Hash(
  contractId: string,
  message: TypedMessage,
  chainId: number,
): Buffer {
  const domainHash = sha256(serializeClarityValue(buildDomain(contractId, chainId)));
  const messageHash = sha256(serializeClarityValue(buildMessageTuple(message)));
  return sha256(Buffer.concat([SIP018_PREFIX, domainHash, messageHash]));
}

// ─── Transfer message builder ─────────────────────────────────────────────────

export interface TransferState {
  pipeKey: { 'principal-1': string; 'principal-2': string; token?: string | null };
  forPrincipal: string;
  myBalance: string;
  theirBalance: string;
  nonce: string;
  action: string;
  actor: string;
  hashedSecret: string | null;
  validAfter: string | null;
}

/**
 * Build the SIP-018 TypedMessage for a StackFlow transfer.
 * Applies canonical balance ordering: balance-1 belongs to principal-1 in pipeKey.
 */
export function buildTransferMessage(state: TransferState): TypedMessage {
  const localIsPrincipal1 = state.pipeKey['principal-1'] === state.forPrincipal;
  const balance1 = localIsPrincipal1 ? state.myBalance : state.theirBalance;
  const balance2 = localIsPrincipal1 ? state.theirBalance : state.myBalance;
  return {
    'principal-1': { type: 'principal', value: state.pipeKey['principal-1'] },
    'principal-2': { type: 'principal', value: state.pipeKey['principal-2'] },
    token: state.pipeKey.token == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'principal', value: state.pipeKey.token } },
    'balance-1': { type: 'uint', value: balance1 },
    'balance-2': { type: 'uint', value: balance2 },
    nonce: { type: 'uint', value: state.nonce },
    action: { type: 'uint', value: state.action },
    actor: { type: 'principal', value: state.actor },
    'hashed-secret': state.hashedSecret == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'buff', value: state.hashedSecret } },
    'valid-after': state.validAfter == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'uint', value: state.validAfter } },
  };
}

// ─── Sign / Verify ────────────────────────────────────────────────────────────

/** Sign a SIP-018 message; returns 65-byte hex: [recovery_id, r, s] */
export async function sip018Sign(
  contractId: string,
  message: TypedMessage,
  privateKeyHex: string,
  chainId: number,
): Promise<string> {
  const { secp256k1 } = await import('@noble/curves/secp256k1');
  const hash = computeSip018Hash(contractId, message, chainId);
  const privKey = Buffer.from(privateKeyHex.replace(/^0x/, ''), 'hex');
  const sig = secp256k1.sign(hash, privKey, { lowS: true });
  const compact = sig.toCompactRawBytes();
  const full = Buffer.concat([Buffer.from([sig.recovery ?? 0]), Buffer.from(compact)]);
  return '0x' + full.toString('hex');
}

/**
 * Verify a SIP-018 signature by recovering the public key from the signature
 * and checking it maps to the expectedAddress.
 * Handles 65-byte [recovery_id, r, s] format.
 */
export async function sip018Verify(
  contractId: string,
  message: TypedMessage,
  signatureHex: string,
  expectedAddress: string,
  chainId: number,
): Promise<boolean> {
  try {
    const { secp256k1 } = await import('@noble/curves/secp256k1');
    const { pubkeyToStxAddress } = await import('./auth.js');

    const hash = computeSip018Hash(contractId, message, chainId);
    const sigBytes = Buffer.from(signatureHex.replace(/^0x/, ''), 'hex');

    let recoveryId: number;
    let compact: Uint8Array;

    if (sigBytes.length === 65) {
      recoveryId = sigBytes[0];
      compact = sigBytes.subarray(1);
    } else if (sigBytes.length === 64) {
      // No recovery byte — try both recovery IDs
      for (const rid of [0, 1]) {
        try {
          const sig = secp256k1.Signature.fromCompact(sigBytes).addRecoveryBit(rid);
          const pubkeyBytes = sig.recoverPublicKey(hash).toRawBytes(true);
          const pubkeyHex = Buffer.from(pubkeyBytes).toString('hex');
          if (
            pubkeyToStxAddress(pubkeyHex) === expectedAddress ||
            pubkeyToStxAddress(pubkeyHex, true) === expectedAddress
          ) return true;
        } catch { /* try next */ }
      }
      return false;
    } else {
      return false;
    }

    const sig = secp256k1.Signature.fromCompact(compact).addRecoveryBit(recoveryId);
    const pubkeyBytes = sig.recoverPublicKey(hash).toRawBytes(true);
    const pubkeyHex = Buffer.from(pubkeyBytes).toString('hex');
    return (
      pubkeyToStxAddress(pubkeyHex) === expectedAddress ||
      pubkeyToStxAddress(pubkeyHex, true) === expectedAddress
    );
  } catch {
    return false;
  }
}
