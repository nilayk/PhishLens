/**
 * The shared vocabulary of PhishLens.
 *
 * Nothing in this file may import from `chrome`, the DOM, or Gmail. These types are the contract
 * between the mail adapter (which knows about Gmail) and the analysis engine (which must not).
 */

// ---------------------------------------------------------------------------
// Extracted message
// ---------------------------------------------------------------------------

/** A hyperlink as the *user sees it* and as it *actually resolves*. Both halves matter. */
export interface EmailLink {
  /** Anchor text exactly as displayed. Hostile input. */
  text: string;
  /** The raw `href` attribute. Hostile input; may be malformed, relative, or a non-web scheme. */
  href: string;
  /**
   * Lowercased, trailing-dot-stripped, `www.`-stripped hostname of `href`, or `''` when the href
   * could not be parsed as an absolute URL.
   */
  normalizedDomain: string;
}

/** Filename evidence only. Attachments are never downloaded, opened, or hashed. */
export interface EmailAttachment {
  /** Filename exactly as displayed. Hostile input; may contain Unicode direction overrides. */
  filename: string;
  /** Lowercased final extension without the dot, or `''` if there is none. */
  extension: string;
}

export type AuthVerdict = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unknown';

/**
 * Authentication information as surfaced by Gmail's UI (not real headers — a content script cannot
 * read RFC 5322 headers). Every field is best-effort and frequently absent.
 */
export interface EmailAuthInfo {
  spf?: AuthVerdict;
  dkim?: AuthVerdict;
  dmarc?: AuthVerdict;
  /** Gmail's "signed-by" value, i.e. the DKIM `d=` domain. */
  signedBy?: string;
  /** Gmail's "mailed-by" value, i.e. the SPF-authenticated envelope domain. */
  mailedBy?: string;
  /** Gmail's "via" annotation, shown when the sending host differs from the From domain. */
  via?: string;
  /** Gmail warned about the sender in its own UI (e.g. the red "be careful with this message" banner). */
  gmailWarning?: string;
  /** Gmail rendered an unauthenticated-sender indicator (the `?` avatar). */
  unauthenticatedIndicator?: boolean;
}

/** A party the mail client showed as the sender of a message in the conversation. */
export interface ThreadParticipant {
  /** Lowercased address, or `''` when the header named none. Hostile input. */
  email: string;
  /** Display name exactly as shown, or `''` when absent. Hostile input. */
  name: string;
}

/**
 * What the conversation looked like *before* the assessed message.
 *
 * Present so detection can ask whether a reply came from a party already in the thread, which is the
 * only way to see a reply-chain hijack: the attacker's message quotes a genuine history, so judged on
 * its own it looks like ordinary correspondence.
 *
 * Read from message headers already rendered on screen — never from a message body, which is
 * attacker-controlled and one `<span email="…">` away from inventing a participant.
 */
export interface ThreadContext {
  /** Senders of the messages above the assessed one, oldest first, including the reader's own. */
  priorSenders: ThreadParticipant[];
}

export interface EmailMessage {
  senderName?: string;
  senderEmail?: string;
  replyTo?: string;
  subject?: string;
  /** Visible body text only. Never HTML. Truncated by the adapter. */
  bodyText: string;
  links: EmailLink[];
  attachments: EmailAttachment[];
  auth?: EmailAuthInfo;
  /** The mailbox the message was delivered to, when available. Used for self-addressing checks. */
  recipientEmail?: string;
  /** Opaque provider identifiers, used only for change detection and never sent anywhere. */
  messageId?: string;
  threadId?: string;
  /** The conversation this message arrived into. Absent when it is the only message on screen. */
  thread?: ThreadContext;
  /** Un-normalised forms of fields whose *formatting* is itself evidence. See `RawFields`. */
  raw?: RawFields;
}

/**
 * Fields exactly as the mail client presented them, before normalisation.
 *
 * Normalisation makes comparison meaningful but destroys evidence: case folding hides
 * `DoNoT.rEpLy.DoNoT.rEpLy@…`, and collapsing whitespace hides a subject padded with 700 spaces. The
 * normalised fields stay canonical and these carry the originals alongside.
 *
 * **Only detectors that examine formatting may read these.** Comparing a raw value against a domain,
 * brand, or another address reintroduces the bugs normalisation prevents, since two spellings of one
 * address would no longer be equal.
 */
export interface RawFields {
  /** Sender address with its original case. */
  senderEmail?: string;
  /** Subject with its original whitespace. */
  subject?: string;
}

/**
 * A part of a message the extraction has to find for the score to mean anything.
 *
 * Named so that "the adapter could not read this" can be *reported* instead of silently becoming an
 * absent field. Every field of `EmailMessage` is optional, which is right — real mail is missing
 * things — but it makes a Gmail markup change indistinguishable from a message that simply has no
 * sender, and those two want opposite treatment.
 *
 * Lives here rather than in `gmail/` because the UI has to name the gap and must not import a mail
 * adapter to do it.
 */
export type MessagePart = 'sender' | 'subject' | 'body';

// ---------------------------------------------------------------------------
// Signals & results
// ---------------------------------------------------------------------------

export type SignalCategory =
  | 'identity'
  | 'link'
  | 'attachment'
  | 'content'
  | 'authentication'
  | 'llm';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Classification = 'low' | 'caution' | 'suspicious' | 'high-risk';

export interface SignalEvidence {
  /** A short excerpt of message text this signal is about. Used for in-message highlighting. */
  text?: string;
  /** A non-URL value, e.g. a domain or filename. */
  value?: string;
  /** The resolved URL this signal is about. Used to locate the anchor for highlighting. */
  url?: string;
}

export interface SecuritySignal {
  id: string;
  category: SignalCategory;
  severity: Severity;
  /** Raw contribution, before per-severity capping and category capping. */
  score: number;
  title: string;
  description: string;
  evidence?: SignalEvidence;
  /**
   * Set when false-positive review softened this finding because the sender is provably the
   * organisation it claims to be.
   *
   * It still scores, at a reduced weight, but it no longer counts as independent technical
   * corroboration: the reason it was softened is that a verified sender already explains it.
   */
  dampened?: boolean;
}

export type SemanticSource = 'none' | 'local' | 'cloud' | 'server';

export interface AnalysisResult {
  /** 0–100, integer. */
  score: number;
  classification: Classification;
  signals: SecuritySignal[];
  /**
   * Per-category capped subtotals, which the UI shows so the score can be checked rather than trusted.
   *
   * They sum to `score` except when a severe finding established a minimum, where the sum is lower —
   * see `SCORE_FLOORS`. The panel labels that case rather than leaving the sum looking wrong.
   */
  categoryScores: Record<SignalCategory, number>;
  /** The raw semantic verdict, kept separate so the UI never blends it with proven findings. */
  semantic?: SemanticAnalysis;
  meta: {
    analyzedAt: number;
    engineVersion: string;
    semanticSource: SemanticSource;
    /**
     * How the semantic stage ended. Absent on a purely deterministic result, where no semantic stage
     * was attempted at all.
     */
    semanticStatus?: SemanticStatus;
  };
}

// ---------------------------------------------------------------------------
// Semantic (LLM) layer
// ---------------------------------------------------------------------------

export const SEMANTIC_CATEGORIES = [
  'credential_phishing',
  'brand_impersonation',
  'business_email_compromise',
  'malware_delivery',
  'payment_fraud',
  'gift_card_scam',
  'social_engineering',
  'unusual_request',
  'benign',
] as const;

export type SemanticCategory = (typeof SEMANTIC_CATEGORIES)[number];

export interface SemanticAnalysis {
  /** 0–100 as judged by the model. Advisory only; capped by the `llm` category weight. */
  risk: number;
  categories: SemanticCategory[];
  /** Short natural-language justifications. Rendered as text, never as markup. */
  reasons: string[];
  /** 0–1. */
  confidence: number;
  source: Exclude<SemanticSource, 'none'>;
  model?: string;
}

/**
 * How the semantic stage ended, as distinct from what it concluded.
 *
 * The UI needs the distinction because "no assessment" has several causes that mean opposite things to
 * a reader: a browser with no model, a model that declined to answer, and a model still thinking all
 * look like silence. `pending` is part of the same union though it never appears on a finished result,
 * so the UI switches on one value rather than on a flag plus a status.
 */
export type SemanticStatus =
  /** An assessment was produced. */
  | 'ready'
  /** Inference is in flight; the score on screen may still change. */
  | 'pending'
  /** The user switched AI analysis off. */
  | 'off'
  /** No model in this browser, or the cloud backend is not configured. */
  | 'unavailable'
  /** The model ran but returned nothing that passed schema validation. */
  | 'no-output'
  /** The model is present but this attempt failed — a timeout, or a rejected session. */
  | 'error'
  /**
   * The attempt was abandoned because the reader moved on. The only status that says nothing about
   * either the message or the browser, and so the only one that must never be cached — see
   * `isSemanticSettled`.
   */
  | 'cancelled';

export interface SemanticAnalyzeOptions {
  /**
   * Abandons the inference when it aborts. Set when the reader moves to another message, so a
   * superseded analysis stops occupying a model that processes one request at a time.
   */
  signal?: AbortSignal;
}

export interface SemanticAnalyzer {
  readonly id: string;
  isAvailable(): Promise<boolean>;
  analyze(email: EmailMessage, options?: SemanticAnalyzeOptions): Promise<SemanticAnalysis | null>;
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/**
 * `local` is Chrome's built-in model; `server` is a model the user runs themselves and reaches over
 * HTTP. Both are "local" in ordinary speech, which is why the options page names them by what they are
 * rather than by these values.
 */
export type AiMode = 'off' | 'local' | 'cloud' | 'server';

export interface Settings {
  /** Default is `local`: on-device only. Neither network mode is ever the default. */
  aiMode: AiMode;
  /** Highlight suspicious links/text in the message when a finding is focused. */
  highlightEnabled: boolean;
  /** Show the badge even for low-risk messages. */
  showBadgeWhenLow: boolean;
  /**
   * Base URL of *our own* analysis backend. Empty in the MVP; the cloud adapter is inert without
   * it. This is never a model-vendor endpoint and never carries a vendor API key.
   */
  backendBaseUrl: string;
  /**
   * OpenAI-compatible base URL of a model server the user runs, as its own documentation gives it —
   * `http://localhost:11434/v1` for Ollama, `http://localhost:12434/engines/v1` for Docker Model
   * Runner. `/chat/completions` is appended to it.
   */
  modelBaseUrl: string;
  /** Model name to request, as that server names it. No default: there is no model we can assume. */
  modelName: string;
}
