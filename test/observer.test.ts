/**
 * Tests for the SPA message observer.
 *
 * This class decides *whether the extension does anything at all*, and every one of its negative
 * decisions is deliberately silent — a wrong `return false` produces no error, no badge, and no log in
 * a production build. That combination is why it needs direct tests rather than coverage via the
 * analysis stack.
 *
 * The regression that motivated these: the staleness guard compared the route's conversation id
 * (`FMfcgz…`) against the DOM's thread perm id (`thread-f:…`). Those are two different Gmail id
 * namespaces for the same thread, so the comparison rejected every message and the extension silently
 * never analysed anything on a real inbox.
 *
 * Runs without a DOM. The observer touches only `window` events, `MutationObserver` and timers, so
 * those are faked here rather than pulling in jsdom for one test file.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { MailAdapter, MessageHandle } from '../src/gmail/adapter.js';
import { GmailObserver, domSignature, viewSignature, type ObserverEvent } from '../src/gmail/observer.js';
import type { EmailMessage } from '../src/shared/types.js';

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

interface RenderedView {
  messageId: string;
  threadId: string;
  senderEmail: string;
  subject: string;
  bodyText: string;
}

/** A Gmail stand-in whose route and rendered DOM can be moved independently, as Gmail's really are. */
class FakeAdapter implements MailAdapter {
  readonly id = 'fake';
  route = '';
  view: RenderedView | null = null;
  rootAvailable = true;

  observationRoot(): Element | null {
    return this.rootAvailable ? ({ tagName: 'DIV' } as unknown as Element) : null;
  }

  /**
   * Mirrors `GmailDomAdapter.routeThreadId()`, including its contract that a list route such as
   * `inbox` or `search/invoices` yields no thread id. A fake that returned the raw hash would let
   * list-view tests pass for the wrong reason.
   */
  routeThreadId(): string {
    const segments = this.route.split('/').filter((s) => s !== '');
    const last = segments[segments.length - 1] ?? '';
    return /^[A-Za-z0-9_-]{16,}$/u.test(last) ? last : '';
  }

  currentMessage(): MessageHandle | null {
    if (this.view === null) return null;
    return {
      messageId: this.view.messageId,
      threadId: this.view.threadId,
      headerElement: null,
      bodyElement: null,
      root: {} as Element,
    };
  }

  extract(): EmailMessage {
    const view = this.view;
    if (view === null) return { bodyText: '', links: [], attachments: [] };
    return {
      senderEmail: view.senderEmail,
      subject: view.subject,
      bodyText: view.bodyText,
      links: [],
      attachments: [],
    };
  }
}

class FakeMutationObserver {
  static instances: FakeMutationObserver[] = [];
  readonly callback: () => void;

  constructor(callback: () => void) {
    this.callback = callback;
    FakeMutationObserver.instances.push(this);
  }

  observe(): void {
    // The observer only needs the callback handle; what it observes is irrelevant here.
  }

  disconnect(): void {
    // No-op.
  }
}

function triggerMutation(): void {
  const observers = FakeMutationObserver.instances;
  const latest = observers[observers.length - 1];
  latest?.callback();
}

/**
 * A thread as Gmail actually presents it: an opaque conversation id in the hash, and an unrelated
 * `thread-f:` perm id on the subject element.
 */
function thread(name: string, permId: string): RenderedView {
  return {
    messageId: `msg-${name}`,
    threadId: `thread-f:${permId}`,
    senderEmail: `sender@${name}.example`,
    subject: `Subject ${name}`,
    bodyText: `Body of ${name}, long enough to be a real message.`,
  };
}

const THREAD_A_HASH = 'FMfcgzQhWLMhlXGCZNdTpfpfWQXRPjNz';
const THREAD_B_HASH = 'FMfcgzGxSVbKjRnQPmWdTzXvLhYcNqBt';

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

let adapter: FakeAdapter;
let events: ObserverEvent[];
let observer: GmailObserver;

function messageEvents(): ObserverEvent[] {
  return events.filter((e) => e.kind === 'message');
}

function noMessageReasons(): string[] {
  return events.flatMap((e) => (e.kind === 'no-message' ? [e.reason] : []));
}

/** Runs long enough for the debounce and at least one reconciliation poll to fire. */
function settle(ms = 500): void {
  vi.advanceTimersByTime(ms);
}

function navigate(hash: string): void {
  adapter.route = hash;
  window.dispatchEvent(new Event('hashchange'));
}

beforeEach(() => {
  vi.useFakeTimers();
  FakeMutationObserver.instances = [];

  Object.defineProperty(globalThis, 'window', {
    value: new EventTarget(),
    configurable: true,
    writable: true,
  });
  Object.defineProperty(globalThis, 'document', {
    value: { body: { tagName: 'BODY' } },
    configurable: true,
    writable: true,
  });
  Object.defineProperty(globalThis, 'MutationObserver', {
    value: FakeMutationObserver,
    configurable: true,
    writable: true,
  });

  adapter = new FakeAdapter();
  events = [];
  observer = new GmailObserver(adapter, (event) => {
    events.push(event);
  });
});

afterEach(() => {
  observer.stop();
  vi.useRealTimers();
  Reflect.deleteProperty(globalThis, 'window');
  Reflect.deleteProperty(globalThis, 'document');
  Reflect.deleteProperty(globalThis, 'MutationObserver');
});

// ---------------------------------------------------------------------------
// The regression
// ---------------------------------------------------------------------------

describe('route id and DOM thread id namespaces', () => {
  it('emits for a message whose DOM thread id shares no namespace with the route id', () => {
    // Exactly the live-Gmail shape: hash says `FMfcgz…`, the subject element says `thread-f:…`.
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1798123456789012345');

    observer.start();
    settle();

    expect(messageEvents()).toHaveLength(1);
    expect(noMessageReasons()).not.toContain('reconciliation-timeout');
  });

  it('emits even when the DOM exposes no thread id at all', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = { ...thread('a', 'x'), threadId: '' };

    observer.start();
    settle();

    expect(messageEvents()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Redundancy
// ---------------------------------------------------------------------------

describe('redundant re-render suppression', () => {
  it('does not re-emit while the same message stays on screen', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');

    observer.start();
    settle();
    expect(messageEvents()).toHaveLength(1);

    // Gmail churns the subtree constantly: avatars, timestamps, ads.
    triggerMutation();
    settle();
    triggerMutation();
    settle();

    expect(messageEvents()).toHaveLength(1);
  });

  it('re-emits when the body arrives after the header', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = { ...thread('a', '1'), bodyText: '' };

    observer.start();
    settle();
    // An empty body is not a message worth reporting.
    expect(messageEvents()).toHaveLength(0);

    adapter.view = thread('a', '1');
    triggerMutation();
    settle();

    expect(messageEvents()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Staleness
// ---------------------------------------------------------------------------

describe('staleness guard', () => {
  it('does not attribute the previous thread to a newly routed thread', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();
    expect(messageEvents()).toHaveLength(1);

    // Route moves to B while Gmail still shows A.
    navigate(THREAD_B_HASH);
    settle(300);

    // Nothing new reported: the only message event is still A's.
    expect(messageEvents()).toHaveLength(1);
    expect(noMessageReasons()).toContain('navigated-away');
  });

  it('emits once the DOM catches up with the new route', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();

    navigate(THREAD_B_HASH);
    settle(200);
    expect(messageEvents()).toHaveLength(1);

    adapter.view = thread('b', '2');
    settle();

    const emitted = messageEvents();
    expect(emitted).toHaveLength(2);
    expect(emitted[1]?.kind === 'message' && emitted[1].email.senderEmail).toBe('sender@b.example');
  });

  it('reports a timeout rather than a stale badge when the DOM never catches up', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();

    navigate(THREAD_B_HASH);
    settle(5000);

    expect(messageEvents()).toHaveLength(1);
    expect(noMessageReasons()).toContain('reconciliation-timeout');
  });

  /**
   * The guard must key on "the route changed", not merely "the DOM looks the same as last time".
   * Re-opening a thread renders a byte-identical view, and that is a legitimate emit.
   */
  it('re-emits when the same thread is re-opened from the list view', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();
    expect(messageEvents()).toHaveLength(1);

    // Back to the inbox list: no thread in the route, no message rendered.
    adapter.view = null;
    navigate('inbox');
    settle();
    expect(noMessageReasons()).toContain('navigated-away');

    // Same thread re-opened; the rendered view is identical to before.
    adapter.view = thread('a', '1');
    navigate(THREAD_A_HASH);
    settle();

    expect(messageEvents()).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// List views
// ---------------------------------------------------------------------------

describe('list views', () => {
  it('reads the thread id from a full Gmail hash route', () => {
    adapter.route = `inbox/${THREAD_A_HASH}`;
    adapter.view = thread('a', '1');

    observer.start();
    settle();

    expect(messageEvents()).toHaveLength(1);
  });

  it('treats a non-thread route as no open message', () => {
    adapter.route = 'inbox';
    adapter.view = thread('a', '1');

    observer.start();
    settle();

    expect(messageEvents()).toHaveLength(0);
  });

  it('tears down when navigating from a thread to a list', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();

    navigate('search/invoices');
    settle();

    expect(noMessageReasons()).toContain('navigated-away');
  });
});

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

describe('lifecycle', () => {
  it('emits nothing after stop', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();
    const before = messageEvents().length;

    observer.stop();
    adapter.view = thread('b', '2');
    adapter.route = THREAD_B_HASH;
    settle();

    expect(messageEvents()).toHaveLength(before);
  });

  it('re-emits the current message on refresh', () => {
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');
    observer.start();
    settle();
    expect(messageEvents()).toHaveLength(1);

    observer.refresh();
    settle();

    expect(messageEvents()).toHaveLength(2);
  });

  it('survives an observation root that is not there yet', () => {
    adapter.rootAvailable = false;
    adapter.route = THREAD_A_HASH;
    adapter.view = thread('a', '1');

    expect(() => {
      observer.start();
      settle();
    }).not.toThrow();
    expect(messageEvents()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

describe('signatures', () => {
  const handle = (messageId: string, threadId: string): MessageHandle => ({
    messageId,
    threadId,
    headerElement: null,
    bodyElement: null,
    root: {} as Element,
  });

  const email = (overrides: Partial<EmailMessage> = {}): EmailMessage => ({
    senderEmail: 'a@example.com',
    subject: 'Hello',
    bodyText: 'Body',
    links: [],
    attachments: [],
    ...overrides,
  });

  it('separates route identity from DOM identity', () => {
    const dom = domSignature(handle('m1', 't1'), email());

    expect(viewSignature(THREAD_A_HASH, handle('m1', 't1'), email())).toBe(`${THREAD_A_HASH}|${dom}`);
    // The same rendered message under a different route has the same DOM signature.
    expect(domSignature(handle('m1', 't1'), email())).toBe(dom);
  });

  it('changes when the body length changes', () => {
    const before = domSignature(handle('m1', 't1'), email({ bodyText: 'short' }));
    const after = domSignature(handle('m1', 't1'), email({ bodyText: 'considerably longer body' }));

    expect(after).not.toBe(before);
  });

  it('changes when the sender changes under a reused message id', () => {
    const before = domSignature(handle('m1', 't1'), email({ senderEmail: 'a@example.com' }));
    const after = domSignature(handle('m1', 't1'), email({ senderEmail: 'b@example.com' }));

    expect(after).not.toBe(before);
  });
});
