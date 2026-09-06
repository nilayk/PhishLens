/**
 * Detects *which message the user is currently reading* in a hash-routed SPA.
 *
 * Neither available signal works alone:
 *
 *  - **`hashchange`/`popstate` alone** fires while Gmail is still showing the *previous* thread.
 *    Extracting at that moment analyses the old message and attributes the result to the new one —
 *    a stale analysis, which is worse than no analysis in a security tool.
 *  - **`MutationObserver` alone** fires dozens of times per thread open (avatars resolving, quoted
 *    text collapsing, the chat roster, ads) and also fires when Gmail re-renders the *same* thread.
 *    That produces redundant re-analysis and a flickering badge.
 *
 * So both are used, reconciled through a single **view signature**:
 *
 *     routeThreadId | domMessageId | domThreadId | fingerprint(sender, subject, bodyLength)
 *
 *  - The debounced observer recomputes the signature. **Unchanged signature → no emit.** That is what
 *    stops redundant re-analysis on a same-thread re-render.
 *  - A route change records the expected thread id and starts a bounded reconciliation poll. An emit
 *    only happens once the DOM has moved on from the view we last reported. **A route change whose DOM
 *    has not caught up produces nothing, rather than a result for the previous thread.** That is what
 *    stops staleness.
 *  - If reconciliation times out, `no-message` is emitted so the UI tears the badge down instead of
 *    leaving a stale one attached to the wrong message.
 *
 * The staleness guard compares **the DOM against itself**, never the route against the DOM. Gmail's
 * hash route carries a conversation id (`FMfcgz…`) while the subject element carries a thread perm id
 * (`thread-f:…`); they identify the same thread in two different id namespaces and are never equal, so
 * an equality test between them rejects every message forever. What is comparable is the previously
 * rendered DOM view: while it is unchanged after a route change, Gmail has not caught up yet.
 *
 * The guard is conditioned on the route having actually changed since the last emit. Re-entering the
 * same thread (open → back to the list → open again) legitimately re-renders an identical view, and
 * must not be mistaken for a DOM that has failed to catch up.
 *
 * The fingerprint component matters beyond thread identity: Gmail reuses message-id attributes when
 * expanding a collapsed message in place, and it renders the header before the body has loaded.
 * Including the body length means "same thread, but the body has now actually arrived" is a change,
 * so the first emit is against a complete message rather than an empty one.
 */
import { logger } from '../shared/logger.js';
import type { EmailMessage } from '../shared/types.js';
import type { MailAdapter, MessageHandle } from './adapter.js';

export interface MessageOpenedEvent {
  kind: 'message';
  signature: string;
  handle: MessageHandle;
  email: EmailMessage;
}

export interface NoMessageEvent {
  kind: 'no-message';
  reason: 'navigated-away' | 'reconciliation-timeout' | 'no-open-message';
}

export type ObserverEvent = MessageOpenedEvent | NoMessageEvent;

export interface ObserverOptions {
  /** Quiet period after DOM churn before re-evaluating. */
  debounceMs?: number;
  /** Interval between reconciliation attempts after a route change. */
  reconcileIntervalMs?: number;
  /** Give up reconciling after this long. */
  reconcileTimeoutMs?: number;
}

const DEFAULTS = {
  debounceMs: 200,
  reconcileIntervalMs: 120,
  reconcileTimeoutMs: 4000,
} as const;

export class GmailObserver {
  readonly #adapter: MailAdapter;
  readonly #onEvent: (event: ObserverEvent) => void;
  readonly #options: Required<ObserverOptions>;

  #mutationObserver: MutationObserver | null = null;
  #debounceTimer: ReturnType<typeof setTimeout> | null = null;
  #reconcileTimer: ReturnType<typeof setInterval> | null = null;
  #reconcileDeadline = 0;

  /** Signature of the last emitted message. The redundancy guard. */
  #lastSignature = '';
  /**
   * The route and DOM identity of the last message actually emitted. The staleness guard compares the
   * current DOM against `domSignature` when the route has moved on from `routeThreadId`.
   */
  #lastEmit: { routeThreadId: string; domSignature: string } | null = null;
  /** Thread id the *route* says should be on screen, used to detect route changes. */
  #expectedThreadId = '';
  #started = false;

  constructor(
    adapter: MailAdapter,
    onEvent: (event: ObserverEvent) => void,
    options: ObserverOptions = {},
  ) {
    this.#adapter = adapter;
    this.#onEvent = onEvent;
    this.#options = { ...DEFAULTS, ...options };
  }

  start(): void {
    if (this.#started) return;
    this.#started = true;

    window.addEventListener('hashchange', this.#handleRouteChange, { passive: true });
    window.addEventListener('popstate', this.#handleRouteChange, { passive: true });

    this.#attachMutationObserver();
    // Gmail's conversation root may not exist yet at document_idle.
    this.#handleRouteChange();
    this.#scheduleEvaluation();
  }

  stop(): void {
    if (!this.#started) return;
    this.#started = false;

    window.removeEventListener('hashchange', this.#handleRouteChange);
    window.removeEventListener('popstate', this.#handleRouteChange);
    this.#mutationObserver?.disconnect();
    this.#mutationObserver = null;
    this.#clearDebounce();
    this.#stopReconciling();
    this.#lastSignature = '';
    this.#lastEmit = null;
    this.#expectedThreadId = '';
  }

  /** Forces a re-evaluation, e.g. after a settings change. */
  refresh(): void {
    this.#lastSignature = '';
    this.#scheduleEvaluation();
  }

  #attachMutationObserver(): void {
    const root = this.#adapter.observationRoot() ?? document.body;
    this.#mutationObserver?.disconnect();
    this.#mutationObserver = new MutationObserver(() => {
      this.#scheduleEvaluation();
    });
    this.#mutationObserver.observe(root, {
      childList: true,
      subtree: true,
      // Attribute and character-data mutations are the noisiest and least informative: Gmail
      // constantly toggles classes and updates relative timestamps. Structural changes are what
      // indicate a different message.
      attributes: false,
      characterData: false,
    });
    logger.debug('mutation observer attached', { root: root.tagName });
  }

  readonly #handleRouteChange = (): void => {
    const threadId = this.#adapter.routeThreadId();

    if (threadId === '') {
      // Navigated to a list view; there is no open message to report on.
      this.#expectedThreadId = '';
      this.#stopReconciling();
      if (this.#lastSignature !== '') {
        this.#lastSignature = '';
        this.#onEvent({ kind: 'no-message', reason: 'navigated-away' });
      }
      return;
    }

    if (threadId === this.#expectedThreadId) return;

    this.#expectedThreadId = threadId;
    // The previous thread's badge must go immediately; it describes a message no longer on screen.
    if (this.#lastSignature !== '') {
      this.#lastSignature = '';
      this.#onEvent({ kind: 'no-message', reason: 'navigated-away' });
    }
    this.#startReconciling();
  };

  /**
   * Polls until the DOM catches up with the route, or the deadline passes.
   *
   * A poll rather than waiting on mutations because the render that completes a thread open does not
   * reliably produce an observable mutation inside the observed subtree on the first pass — the
   * conversation root itself is sometimes replaced, which detaches the observer.
   */
  #startReconciling(): void {
    this.#stopReconciling();
    this.#reconcileDeadline = Date.now() + this.#options.reconcileTimeoutMs;

    this.#reconcileTimer = setInterval(() => {
      // The observation root may have been swapped out during navigation.
      const root = this.#adapter.observationRoot();
      if (root !== null && this.#mutationObserver === null) this.#attachMutationObserver();

      if (this.#evaluate()) {
        this.#stopReconciling();
        return;
      }
      if (Date.now() > this.#reconcileDeadline) {
        this.#stopReconciling();
        logger.debug('reconciliation timed out', { expected: this.#expectedThreadId });
        this.#onEvent({ kind: 'no-message', reason: 'reconciliation-timeout' });
      }
    }, this.#options.reconcileIntervalMs);
  }

  #stopReconciling(): void {
    if (this.#reconcileTimer !== null) {
      clearInterval(this.#reconcileTimer);
      this.#reconcileTimer = null;
    }
  }

  #scheduleEvaluation(): void {
    this.#clearDebounce();
    this.#debounceTimer = setTimeout(() => {
      this.#debounceTimer = null;
      this.#evaluate();
    }, this.#options.debounceMs);
  }

  #clearDebounce(): void {
    if (this.#debounceTimer !== null) {
      clearTimeout(this.#debounceTimer);
      this.#debounceTimer = null;
    }
  }

  /**
   * The single decision point. Returns `true` when a message event was emitted.
   */
  #evaluate(): boolean {
    if (!this.#started) return false;

    const routeThreadId = this.#adapter.routeThreadId();
    if (routeThreadId === '') {
      if (this.#lastSignature !== '') {
        this.#lastSignature = '';
        this.#onEvent({ kind: 'no-message', reason: 'navigated-away' });
      }
      return false;
    }

    const handle = this.#adapter.currentMessage();
    if (handle === null) return false;

    const email = this.#adapter.extract(handle);

    // A header rendered before its body: wait rather than analysing an empty message.
    if (email.bodyText.trim() === '' && email.links.length === 0 && email.attachments.length === 0) {
      return false;
    }

    // Staleness guard. Route ids and DOM thread ids are different Gmail id namespaces (see the file
    // header), so the DOM is compared against the view we last reported instead. An unchanged view
    // under a changed route means Gmail has not re-rendered yet.
    const domSig = domSignature(handle, email);
    const lastEmit = this.#lastEmit;
    if (
      lastEmit !== null &&
      lastEmit.routeThreadId !== routeThreadId &&
      lastEmit.domSignature === domSig
    ) {
      logger.debug('DOM has not caught up with the route yet', {
        expected: routeThreadId,
        rendered: lastEmit.routeThreadId,
      });
      return false;
    }

    const signature = viewSignature(routeThreadId, handle, email);
    if (signature === this.#lastSignature) return false;

    this.#lastSignature = signature;
    this.#lastEmit = { routeThreadId, domSignature: domSig };
    this.#expectedThreadId = routeThreadId;
    logger.debug('message opened', { signature });
    this.#onEvent({ kind: 'message', signature, handle, email });
    return true;
  }
}

/**
 * Identity of the currently-rendered view.
 *
 * Deliberately includes content-derived components, not just ids: Gmail reuses message ids when
 * expanding a collapsed message in place, and renders headers before bodies. Without the fingerprint
 * we would either miss the transition or analyse a half-rendered message.
 */
export function viewSignature(
  routeThreadId: string,
  handle: MessageHandle,
  email: EmailMessage,
): string {
  return `${routeThreadId}|${domSignature(handle, email)}`;
}

/**
 * Identity of the rendered message, derived purely from the DOM.
 *
 * Deliberately excludes the route, so it can answer "is Gmail still showing what it showed before?"
 * independently of what the URL now claims.
 */
export function domSignature(handle: MessageHandle, email: EmailMessage): string {
  return [
    handle.messageId,
    handle.threadId,
    email.senderEmail ?? '',
    fingerprint(`${email.subject ?? ''}|${String(email.bodyText.length)}|${String(email.links.length)}`),
  ].join('|');
}

/**
 * A cheap non-cryptographic fingerprint (FNV-1a).
 *
 * Only ever compared for equality against another fingerprint from this same function, so collision
 * resistance is irrelevant and a hash function is not a security control here.
 */
export function fingerprint(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(36);
}
