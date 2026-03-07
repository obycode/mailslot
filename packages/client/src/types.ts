// Client-side types

export interface InboxEntry {
  id: string;
  from: string;
  subject?: string;
  sentAt: number;
  amount: string;
  claimed: boolean;
}

export interface MailMessage {
  id: string;
  from: string;
  to: string;
  subject?: string;
  body: string;
  sentAt: number;
  amount: string;
  fee: string;
  paymentId: string;
}

export interface SendOptions {
  to: string;               // recipient STX address
  subject?: string;
  body: string;
  serverUrl: string;        // stackmail server base URL
}

export interface ClientConfig {
  /** Agent's STX address */
  address: string;
  /** Stackmail server base URL */
  serverUrl: string;
  /** Signs SIP-018 messages for inbox auth — returns hex signature */
  signer: (message: string) => Promise<string>;
  /** Builds and returns an x402 indirect payment proof for a given paymentInfo */
  paymentProofBuilder: (paymentInfo: PaymentInfo) => Promise<string>;
}

export interface PaymentInfo {
  paymentId: string;
  hashedSecret: string;
  amount: string;
  fee: string;
  recipientAmount: string;
  stackflowNodeUrl: string;
  serverAddress: string;
  expiresAt: number;
}

export interface PollResult {
  newMessages: InboxEntry[];
  claimedMessages: MailMessage[];
  errors: Array<{ messageId: string; error: string }>;
}
