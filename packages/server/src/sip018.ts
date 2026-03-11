/**
 * SIP-018 structured data hashing and signing for StackFlow transfers.
 *
 * Algorithm:
 *   domain = { chain-id: uint, name: string-ascii, version: string-ascii }
 *   message = { action, actor, balance-1, balance-2, hashed-secret, nonce, principal-1, principal-2, token, valid-after }
 *   hash = sha256("SIP018" || sha256(clarity_serialize(domain)) || sha256(clarity_serialize(message)))
 *
 * Signatures are 65 bytes. Wallets commonly return RSV (r||s||v), while some
 * tooling emits VRS (v||r||s). Verification accepts both forms.
 */

import { createHash } from 'node:crypto';
import { principalCV, serializeCVBytes } from '@stacks/transactions';

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
  // Delegate to canonical principal serialization from @stacks/transactions.
  return Buffer.from(serializeCVBytes(principalCV(value)));
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

/** Sign a SIP-018 message; returns 65-byte RSV hex: [r, s, recovery_id] */
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
  // Emit RSV to match wallet output and Clarity contract expectations.
  const full = Buffer.concat([Buffer.from(compact), Buffer.from([sig.recovery ?? 0])]);
  return '0x' + full.toString('hex');
}

function normalizeRecoveryId(raw: number): number | null {
  if (raw === 0 || raw === 1) return raw;
  if (raw === 27 || raw === 28) return raw - 27;
  return null;
}

function signatureCandidates(sigBytes: Buffer): Array<{ compact: Uint8Array; recoveryId: number }> {
  if (sigBytes.length === 64) {
    return [
      { compact: sigBytes, recoveryId: 0 },
      { compact: sigBytes, recoveryId: 1 },
    ];
  }
  if (sigBytes.length !== 65) return [];

  const out: Array<{ compact: Uint8Array; recoveryId: number }> = [];

  // VRS: [v || r || s]
  const vrsRecovery = normalizeRecoveryId(sigBytes[0]);
  if (vrsRecovery != null) {
    out.push({ compact: sigBytes.subarray(1), recoveryId: vrsRecovery });
  }

  // RSV: [r || s || v]
  const rsvRecovery = normalizeRecoveryId(sigBytes[64]);
  if (rsvRecovery != null) {
    out.push({ compact: sigBytes.subarray(0, 64), recoveryId: rsvRecovery });
  }

  return out;
}

/**
 * Verify a SIP-018 signature by recovering the public key from the signature
 * and checking it maps to the expectedAddress.
 * Accepts both RSV and VRS 65-byte signatures, plus raw 64-byte signatures.
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
    for (const candidate of signatureCandidates(sigBytes)) {
      try {
        const sig = secp256k1.Signature
          .fromCompact(candidate.compact)
          .addRecoveryBit(candidate.recoveryId);
        const pubkeyBytes = sig.recoverPublicKey(hash).toRawBytes(true);
        const pubkeyHex = Buffer.from(pubkeyBytes).toString('hex');
        if (
          pubkeyToStxAddress(pubkeyHex) === expectedAddress ||
          pubkeyToStxAddress(pubkeyHex, true) === expectedAddress
        ) {
          return true;
        }
      } catch {
        // Try the next signature layout/recovery option.
      }
    }
    return false;
  } catch {
    return false;
  }
}
