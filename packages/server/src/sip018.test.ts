import { describe, it, expect } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  bufferCV,
  noneCV,
  principalCV,
  signStructuredData,
  someCV,
  stringAsciiCV,
  tupleCV,
  uintCV,
  type ClarityValue,
} from '@stacks/transactions';

import { pubkeyToStxAddress } from './auth.js';
import { buildTransferMessage, sip018Verify, type TypedField, type TypedMessage } from './sip018.js';

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.replace(/^0x/, '');
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function typedFieldToCV(field: TypedField): ClarityValue {
  switch (field.type) {
    case 'uint':
      return uintCV(BigInt(String(field.value)));
    case 'principal':
      return principalCV(String(field.value));
    case 'buff':
      return bufferCV(hexToBytes(String(field.value)));
    case 'none':
      return noneCV();
    case 'some':
      return someCV(typedFieldToCV(field.value as TypedField));
    case 'string-ascii':
      return stringAsciiCV(String(field.value));
    default:
      throw new Error(`Unsupported typed field: ${field.type}`);
  }
}

function typedMessageToCV(message: TypedMessage): ClarityValue {
  const fields: Record<string, ClarityValue> = {};
  for (const [key, field] of Object.entries(message)) {
    fields[key] = typedFieldToCV(field);
  }
  return tupleCV(fields);
}

describe('sip018Verify', () => {
  it('accepts wallet RSV signatures and rotated VRS signatures', async () => {
    const signerPriv = Buffer.from(secp256k1.utils.randomPrivateKey()).toString('hex');
    const signerPub = secp256k1.getPublicKey(signerPriv, true);
    const signerAddress = pubkeyToStxAddress(Buffer.from(signerPub).toString('hex'));

    const counterpartyPriv = Buffer.from(secp256k1.utils.randomPrivateKey()).toString('hex');
    const counterpartyPub = secp256k1.getPublicKey(counterpartyPriv, true);
    const counterpartyAddress = pubkeyToStxAddress(Buffer.from(counterpartyPub).toString('hex'));

    const contractId = `${signerAddress}.stackflow-test`;
    const message = buildTransferMessage({
      pipeKey: {
        token: null,
        'principal-1': signerAddress < counterpartyAddress ? signerAddress : counterpartyAddress,
        'principal-2': signerAddress < counterpartyAddress ? counterpartyAddress : signerAddress,
      },
      forPrincipal: signerAddress,
      myBalance: '1000',
      theirBalance: '0',
      nonce: '1',
      action: '2',
      actor: signerAddress,
      hashedSecret: null,
      validAfter: null,
    });

    const domain = tupleCV({
      'chain-id': uintCV(1),
      name: stringAsciiCV(contractId),
      version: stringAsciiCV('0.6.0'),
    });
    const rsv = signStructuredData({
      privateKey: signerPriv,
      domain,
      message: typedMessageToCV(message),
    });
    const rsvHex = rsv.startsWith('0x') ? rsv : `0x${rsv}`;
    const raw = rsvHex.replace(/^0x/, '');
    const vrsHex = `0x${raw.slice(-2)}${raw.slice(0, -2)}`;

    expect(await sip018Verify(contractId, message, rsvHex, signerAddress, 1)).toBe(true);
    expect(await sip018Verify(contractId, message, vrsHex, signerAddress, 1)).toBe(true);
  });
});
