/**
 * Per-tab orchestration: observe → extract → analyse → render.
 *
 * This is where the MV3 statefulness decision lands (docs/ARCHITECTURE.md §2). Everything stateful
 * lives here, in the content script, because this context lives as long as the Gmail tab:
 *   - the on-device model session (via `localAnalyzer()`)
 *   - the small bounded result cache
 *   - the badge and panel instances
 *
 * The service worker holds none of it and is only asked for settings, so it can be terminated at any
 * moment without affecting anything in flight.
 */
import {
  analyze,
  analyzeDeterministic,
  isSemanticSettled,
  withSemanticStatus,
} from '../analysis/engine.js';
import { localAnalyzer, resolveAnalyzer } from '../analysis/llm/index.js';
import { isScorable, type MailAdapter, type MessageHandle } from '../gmail/adapter.js';
import { buildDiagnostic } from '../gmail/diagnostics.js';
import { GmailObserver, type ObserverEvent } from '../gmail/observer.js';
import { logger } from '../shared/logger.js';
import { isTabRequest, sendMessage, type TabResponse, type TabStatus } from '../shared/messaging.js';
import { DEFAULT_SETTINGS } from '../shared/settings.js';
import type {
  AiMode,
  AnalysisResult,
  EmailMessage,
  MessagePart,
  SecuritySignal,
  SemanticStatus,
  Settings,
} from '../shared/types.js';
import { Badge } from '../ui/badge.js';
import { Highlighter } from '../ui/highlight.js';
import { Panel, type PanelView, type UnreadableView } from '../ui/panel.js';

/**
 * Bounded in-memory cache so revisiting a thread does not re-run the model.
 *
 * Small on purpose: results are never persisted (they contain findings derived from message content),
 * and the rule engine takes single-digit milliseconds, so there is nothing worth keeping beyond
 * avoiding repeat inference within a browsing session.
 */
const MAX_CACHED_RESULTS = 20;

/** Findings named in the popup. Enough to recognise the verdict; the card is where the reasoning is. */
const POPUP_HEADLINES = 3;

interface ActiveView {
  signature: string;
  handle: MessageHandle;
  email: EmailMessage;
  /** Parts the adapter could not read. Non-empty in a load-bearing part means nothing was scored. */
  missing: readonly MessagePart[];
  result: AnalysisResult | null;
  /**
   * Where the semantic stage has got to *for this view*. Not derivable from the result: "in flight"
   * describes the view, while the result on screen is the deterministic one and is already complete.
   */
  semantic: SemanticStatus;
}

export class Controller {
  readonly #adapter: MailAdapter;
  readonly #observer: GmailObserver;
  readonly #badge: Badge;
  readonly #panel: Panel;
  readonly #highlighter = new Highlighter();
  readonly #cache = new Map<string, AnalysisResult>();

  #settings: Settings = { ...DEFAULT_SETTINGS };
  #active: ActiveView | null = null;
  /** Guards against a slow analysis of a previous message overwriting a newer one. */
  #analysisToken = 0;
  /**
   * Cancels in-flight semantic analysis when the view changes. The token above stops a stale result
   * being *shown*; this stops the work, which matters because the model handles one request at a time.
   */
  #refinement: AbortController | null = null;

  constructor(adapter: MailAdapter) {
    this.#adapter = adapter;

    this.#badge = new Badge({
      onActivate: () => {
        this.#togglePanel();
      },
    });

    this.#panel = new Panel({
      onFocusSignal: (signal) => {
        this.#highlight(signal);
      },
      onBlurSignal: () => {
        this.#highlighter.clear();
      },
      onClose: () => {
        this.#panel.close();
      },
    });

    this.#observer = new GmailObserver(adapter, (event) => {
      void this.#handleObserverEvent(event);
    });
  }

  async start(): Promise<void> {
    this.#settings = await loadSettings();
    logger.info('starting', { aiMode: this.#settings.aiMode, adapter: this.#adapter.id });

    chrome.storage.onChanged.addListener(this.#handleStorageChanged);
    chrome.runtime.onMessage.addListener(this.#handleTabRequest);
    this.#observer.start();
    this.#warmModel();
  }

  stop(): void {
    this.#refinement?.abort();
    this.#refinement = null;
    this.#observer.stop();
    chrome.storage.onChanged.removeListener(this.#handleStorageChanged);
    chrome.runtime.onMessage.removeListener(this.#handleTabRequest);
    this.#panel.close();
    this.#badge.remove();
    this.#highlighter.dispose();
    this.#cache.clear();
    this.#active = null;
  }

  // -------------------------------------------------------------------------
  // Observer
  // -------------------------------------------------------------------------

  async #handleObserverEvent(event: ObserverEvent): Promise<void> {
    // Any inference still running belongs to the view being replaced, whichever kind of event this is.
    this.#refinement?.abort();
    this.#refinement = null;

    if (event.kind === 'no-message') {
      logger.debug('no message in view', { reason: event.reason });
      this.#teardownView();
      return;
    }

    const token = ++this.#analysisToken;
    const aiMode = this.#settings.aiMode;
    const active: ActiveView = {
      signature: event.signature,
      handle: event.handle,
      email: event.email,
      missing: event.missing,
      result: null,
      semantic: aiMode === 'off' ? 'off' : 'pending',
    };
    this.#active = active;

    if (event.handle.headerElement !== null) {
      this.#badge.attach(event.handle.headerElement);
    }

    /*
     * Nothing is scored when a load-bearing part could not be read.
     *
     * The rule engine would happily score it: with no sender there is nothing for the identity,
     * authentication or thread checks to object to, so it returns a near-zero score, `low`, and a green
     * badge — the most reassuring output the extension can produce, at the moment it knows the least.
     * The badge stays, saying so, because removing it would be indistinguishable from a clean message
     * on a `showBadgeWhenLow: false` install. That setting is not consulted here for the same reason:
     * this is not a low reading.
     */
    if (!isScorable(event.missing)) {
      logger.info('message not scored', { missing: event.missing });
      this.#badge.setUnreadable();
      // An open card is repainted, exactly as `#applyResult` does. Moving between messages within one
      // thread is not a route change, so nothing has closed it: without this it would go on displaying
      // the previous message's score beside a badge saying this one was never checked.
      if (this.#panel.isOpen) this.#panel.open(this.#unreadableView(active));
      return;
    }

    const cached = this.#cache.get(event.signature);
    if (cached !== undefined) {
      // Only settled results are cached, so this status is a conclusion rather than a moment in time.
      this.#applyResult(cached, token, cached.meta.semanticStatus ?? 'unavailable');
      return;
    }

    this.#badge.setPending();

    // The deterministic result is rendered first and is complete on its own. If a semantic analyzer
    // is available, the score is then refined. This ordering means the user is never waiting on a
    // model for a verdict, and an unavailable model is invisible rather than a failure state.
    const { context: _context, ...deterministic } = analyzeDeterministic(event.email);
    this.#applyResult(deterministic, token, aiMode === 'off' ? 'off' : 'pending');

    if (aiMode === 'off') return;

    const refinement = new AbortController();
    this.#refinement = refinement;

    try {
      const analyzer = resolveAnalyzer(
        this.#settings,
        deterministic.signals.map((s) => s.id),
      );
      const refined = await analyze(event.email, analyzer, { signal: refinement.signal });
      this.#remember(event.signature, refined);
      this.#applyResult(refined, token, refined.meta.semanticStatus ?? 'no-output');
    } catch (error) {
      // The deterministic result is already on screen; a semantic failure is not a user-facing error.
      // It is still reported *as* a failure rather than left pending, or the card spins forever.
      logger.debug('semantic refinement failed', error);
      const failed = withSemanticStatus(deterministic, 'error');
      this.#remember(event.signature, failed);
      this.#applyResult(failed, token, 'error');
    } finally {
      if (this.#refinement === refinement) this.#refinement = null;
    }
  }

  /** Applies a result only if it belongs to the message currently in view. */
  #applyResult(result: AnalysisResult, token: number, semantic: SemanticStatus): void {
    if (token !== this.#analysisToken) {
      logger.debug('discarding result for a message no longer in view');
      return;
    }
    const active = this.#active;
    if (active === null) return;

    active.result = result;
    active.semantic = semantic;

    if (result.classification !== 'low' || this.#settings.showBadgeWhenLow) {
      if (!this.#badge.isAttached() && active.handle.headerElement !== null) {
        this.#badge.attach(active.handle.headerElement);
      }
      this.#badge.setResult(result);
    } else {
      this.#badge.remove();
    }

    // An open card is updated in place — the refined score replacing the deterministic one, without
    // re-animating or losing the reader's scroll position. This happens whether or not the badge is
    // shown: a refinement that lands on "low" hides the badge, and returning early there used to leave
    // the card displaying the score it had just superseded.
    if (this.#panel.isOpen) {
      this.#panel.open(viewOf(active, result, this.#settings.aiMode));
    }
  }

  #teardownView(): void {
    this.#analysisToken += 1;
    this.#panel.close();
    this.#highlighter.clear();
    this.#badge.remove();
    this.#active = null;
  }

  /**
   * Caches a result, but only if the semantic stage concluded something (see `isSemanticSettled`).
   *
   * Caching an unsettled result makes a passing condition permanent for the life of the tab: a
   * cancelled or timed-out attempt would be replayed from the cache on every later visit, and only a
   * reload would clear it. Not keeping it costs one more inference attempt next time.
   */
  #remember(signature: string, result: AnalysisResult): void {
    if (!isSemanticSettled(result.meta.semanticStatus)) {
      logger.debug('not caching an unsettled result', {
        status: result.meta.semanticStatus ?? 'none',
      });
      return;
    }
    this.#cache.set(signature, result);
    this.#trimCache();
  }

  #trimCache(): void {
    while (this.#cache.size > MAX_CACHED_RESULTS) {
      const oldest = this.#cache.keys().next();
      if (oldest.done === true) break;
      this.#cache.delete(oldest.value);
    }
  }

  // -------------------------------------------------------------------------
  // The popup
  // -------------------------------------------------------------------------

  /**
   * Answers the toolbar popup.
   *
   * Synchronous, and returns `false` so the channel closes immediately: every answer is read from state
   * this object already holds, and keeping the port open for an await would let a popup that closes
   * mid-question leave a dangling response callback.
   *
   * The listener is registered here rather than in `content/index.ts` because the answers are this
   * object's state, and a listener outliving the controller would answer for a torn-down view.
   */
  readonly #handleTabRequest = (
    message: unknown,
    sender: chrome.runtime.MessageSender,
    respond: (response: TabResponse) => void,
  ): boolean => {
    // `sender.id` is set by Chrome. A page cannot forge it, so this rejects anything that did not
    // originate in this extension — the popup being the only thing that ever does.
    if (sender.id !== chrome.runtime.id || !isTabRequest(message)) return false;

    if (message.type === 'OPEN_PANEL') {
      this.#revealPanel();
      respond({ ok: true, type: 'ACKNOWLEDGED' });
      return false;
    }

    respond({ ok: true, type: 'TAB_STATUS', status: this.#status() });
    return false;
  };

  #status(): TabStatus {
    const active = this.#active;
    if (active === null) return { kind: 'no-message' };
    if (!isScorable(active.missing)) return { kind: 'unreadable', missing: [...active.missing] };

    const result = active.result;
    if (result === null) return { kind: 'pending' };

    return {
      kind: 'scored',
      score: result.score,
      classification: result.classification,
      findings: result.signals.length,
      // Already ordered as the card orders them, so these are the findings a reader would see first.
      headlines: result.signals.slice(0, POPUP_HEADLINES).map((signal) => signal.title),
      semantic: active.semantic,
    };
  }

  // -------------------------------------------------------------------------
  // UI
  // -------------------------------------------------------------------------

  #togglePanel(): void {
    const view = this.#currentView();
    if (view !== null) this.#panel.toggle(view);
  }

  /** Opens the card rather than toggling it: the popup's button must not close what it describes. */
  #revealPanel(): void {
    const view = this.#currentView();
    if (view !== null) this.#panel.open(view);
  }

  /** What the card would show for the message in view, or `null` while there is nothing to show. */
  #currentView(): PanelView | null {
    const active = this.#active;
    if (active === null) return null;
    if (!isScorable(active.missing)) return this.#unreadableView(active);
    if (active.result === null) return null;
    return viewOf(active, active.result, this.#settings.aiMode);
  }

  /**
   * The card's input for a message that was not scored.
   *
   * The selector probe runs here rather than during extraction: it walks every candidate list, and the
   * overwhelmingly common case is that this card is never shown at all.
   */
  #unreadableView(active: ActiveView): UnreadableView {
    return {
      kind: 'unreadable',
      email: active.email,
      missing: active.missing,
      diagnostic: buildDiagnostic(active.handle, active.missing, this.#adapter.id),
    };
  }

  /**
   * Builds the on-device session at startup rather than on first use, since creating one costs seconds
   * and that cost would otherwise land on the first message opened. Fire-and-forget.
   */
  #warmModel(): void {
    if (this.#settings.aiMode !== 'local') return;
    void localAnalyzer().warmUp();
  }

  #highlight(signal: SecuritySignal): void {
    if (!this.#settings.highlightEnabled) return;
    const bodyElement = this.#active?.handle.bodyElement ?? null;
    this.#highlighter.show(signal, bodyElement);
  }

  readonly #handleStorageChanged = (
    _changes: Record<string, chrome.storage.StorageChange>,
    areaName: string,
  ): void => {
    if (areaName !== 'sync') return;
    void this.#reloadSettings();
  };

  async #reloadSettings(): Promise<void> {
    const previous = this.#settings;
    this.#settings = await loadSettings();
    logger.debug('settings reloaded', { aiMode: this.#settings.aiMode });

    // Changing AI mode invalidates every cached result, since the llm contribution differs.
    if (previous.aiMode !== this.#settings.aiMode) {
      this.#cache.clear();
      this.#warmModel();
      this.#observer.refresh();
    }
  }
}

/** The result is passed separately so this cannot be called before there is one to render. */
function viewOf(active: ActiveView, result: AnalysisResult, aiMode: AiMode): PanelView {
  return { kind: 'result', result, aiMode, email: active.email, semantic: active.semantic };
}

/** Reads settings via the worker, falling back to defaults if it is mid-restart. */
async function loadSettings(): Promise<Settings> {
  const response = await sendMessage({ type: 'GET_SETTINGS' });
  if (response !== null && response.ok && response.type === 'SETTINGS') return response.settings;
  return { ...DEFAULT_SETTINGS };
}
