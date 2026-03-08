/**
 * Payment service — inline StackFlow reservoir.
 *
 * Replaces the former HTTP-based SF-node dependency. The server now acts as
 * its own reservoir operator: it verifies incoming HTLC proofs inline,
 * signs outgoing state updates with its own key, and tracks pipe state locally.
 */

export { ReservoirError as PaymentError } from './reservoir.js';
export type { VerifiedPayment } from './reservoir.js';
export { ReservoirService as PaymentService } from './reservoir.js';
