/**
 * The mail-client abstraction.
 *
 * `src/analysis/` depends on `EmailMessage` and nothing else. This interface is the seam: swapping
 * Gmail for another client, or for a test double, means providing another implementation and changing
 * nothing in the detection or scoring layers.
 */
import type { EmailMessage, MessagePart, ThreadParticipant } from '../shared/types.js';

/** An opaque handle to the message currently on screen. */
export interface MessageHandle {
  /** Stable provider id for the message, when available. */
  messageId: string;
  /** Stable provider id for the thread, when available. */
  threadId: string;
  /**
   * Senders of the messages above this one in the conversation, oldest first.
   *
   * Collected here rather than in `extract` because only the code that chose *which* message to assess
   * knows where the boundary between "before" and "after" falls.
   */
  priorSenders: ThreadParticipant[];
  /** The element the badge should be attached near. */
  headerElement: Element | null;
  /** The element containing the rendered body, for link location and highlighting. */
  bodyElement: Element | null;
  /** The container for the whole message, used as the extraction root. */
  root: Element;
}

/**
 * An extracted message, plus which of its parts the adapter could not find.
 *
 * The two are returned together and kept separate. `EmailMessage` describes the mail, and how well the
 * adapter could read the page is not a property of the mail — putting it inside would also let
 * `analysis/` branch on extraction quality, which is the browser layer's business and would make the
 * detection rules untestable without a notion of a broken DOM.
 */
export interface Extraction {
  email: EmailMessage;
  /** Parts the adapter looked for and did not get. Empty when everything was read. */
  missing: readonly MessagePart[];
}

/**
 * Parts whose absence makes a score *misleading* rather than merely less detailed.
 *
 * The sender is the whole reason this concept exists. Identity, authentication, thread and correlation
 * checks all key off the sending domain, so a message with no readable sender produces almost no
 * findings, which the aggregation faithfully turns into a score near zero — a confident "Low Risk" on
 * a message nobody actually checked. That is the one failure direction this project cannot accept, so
 * an unscorable extraction is reported to the reader instead of being scored.
 *
 * A missing subject costs some wording checks and can set no floor, so it is worth recording in a
 * diagnostic and not worth withholding a score over.
 */
const REQUIRED_PARTS: readonly MessagePart[] = ['sender', 'body'];

/** Whether a score built from this extraction would be honest. */
export function isScorable(missing: readonly MessagePart[]): boolean {
  return !missing.some((part) => REQUIRED_PARTS.includes(part));
}

export interface MailAdapter {
  readonly id: string;
  /** The element to observe for in-place re-renders. */
  observationRoot(): Element | null;
  /** The message the user is currently reading, or `null` when no message is open. */
  currentMessage(): MessageHandle | null;
  /** Extracts a normalised message. Never throws; parts it could not read are named in `missing`. */
  extract(handle: MessageHandle): Extraction;
  /** The thread id encoded in the current route, independent of the DOM. */
  routeThreadId(): string;
}
