/**
 * The mail-client abstraction.
 *
 * `src/analysis/` depends on `EmailMessage` and nothing else. This interface is the seam: swapping
 * Gmail for another client, or for a test double, means providing another implementation and changing
 * nothing in the detection or scoring layers.
 */
import type { EmailMessage } from '../shared/types.js';

/** An opaque handle to the message currently on screen. */
export interface MessageHandle {
  /** Stable provider id for the message, when available. */
  messageId: string;
  /** Stable provider id for the thread, when available. */
  threadId: string;
  /** The element the badge should be attached near. */
  headerElement: Element | null;
  /** The element containing the rendered body, for link location and highlighting. */
  bodyElement: Element | null;
  /** The container for the whole message, used as the extraction root. */
  root: Element;
}

export interface MailAdapter {
  readonly id: string;
  /** The element to observe for in-place re-renders. */
  observationRoot(): Element | null;
  /** The message the user is currently reading, or `null` when no message is open. */
  currentMessage(): MessageHandle | null;
  /** Extracts a normalised message. Never throws; missing fields are simply absent. */
  extract(handle: MessageHandle): EmailMessage;
  /** The thread id encoded in the current route, independent of the DOM. */
  routeThreadId(): string;
}
