/**
 * The toolbar popup.
 *
 * Exists because clicking the extension's icon used to do nothing, which is the moment a user decides an
 * extension is half-finished. It answers the three questions asked at that moment: is PhishLens running
 * on this tab, what did it make of the message, and — the one that used to require a DevTools console —
 * is the AI layer actually working.
 *
 * It holds no state and starts no work. Everything shown is read from the tab that already did the
 * analysis, so opening the popup cannot change a score, and closing it cannot cancel anything.
 *
 * Wording lives in `present.ts`, which is pure and tested. This file is the wiring.
 */
import { logger } from '../shared/logger.js';
import { sendMessage, sendTabMessage } from '../shared/messaging.js';
import { DEFAULT_SETTINGS } from '../shared/settings.js';
import type { Settings } from '../shared/types.js';
import { el } from '../ui/dom.js';
import { aiRow, cardButtonLabel, findingsLine, headline, type PopupState } from './present.js';

declare const __PHISHLENS_VERSION__: string;

/** The one site the content script runs on, and so the only tab that can have an answer. */
const GMAIL_ORIGIN = 'https://mail.google.com/';

function requireElement<T extends HTMLElement>(id: string, ctor: new () => T): T {
  const element = document.getElementById(id);
  if (!(element instanceof ctor)) throw new Error(`missing #${id}`);
  return element;
}

/**
 * The active tab's id, if it is a Gmail tab.
 *
 * `tab.url` is only populated for tabs the extension has host access to, which is exactly the check
 * wanted here — and the reason this needs no `tabs` permission. A tab whose URL is hidden from us is a
 * tab we have nothing to say about.
 */
async function gmailTabId(): Promise<number | null> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id === undefined) return null;
    return tab.url?.startsWith(GMAIL_ORIGIN) === true ? tab.id : null;
  } catch (error) {
    logger.debug('could not read the active tab', error);
    return null;
  }
}

class Popup {
  readonly #chip = requireElement('chip', HTMLSpanElement);
  readonly #glyph = requireElement('glyph', HTMLSpanElement);
  readonly #label = requireElement('label', HTMLSpanElement);
  readonly #score = requireElement('score', HTMLSpanElement);
  readonly #note = requireElement('note', HTMLParagraphElement);
  readonly #findings = requireElement('findings', HTMLUListElement);
  readonly #more = requireElement('more', HTMLParagraphElement);
  readonly #openCard = requireElement('openCard', HTMLButtonElement);
  readonly #aiLabel = requireElement('aiLabel', HTMLSpanElement);
  readonly #aiDetail = requireElement('aiDetail', HTMLSpanElement);
  readonly #aiFix = requireElement('aiFix', HTMLParagraphElement);
  readonly #test = requireElement('test', HTMLButtonElement);
  readonly #testResult = requireElement('testResult', HTMLParagraphElement);
  readonly #settings = requireElement('settings', HTMLButtonElement);
  readonly #showBadgeWhenLow = requireElement('showBadgeWhenLow', HTMLInputElement);
  readonly #highlightEnabled = requireElement('highlightEnabled', HTMLInputElement);
  readonly #version = requireElement('version', HTMLSpanElement);

  #tabId: number | null = null;

  async init(): Promise<void> {
    this.#version.textContent =
      typeof __PHISHLENS_VERSION__ === 'undefined' ? 'dev build' : `v${__PHISHLENS_VERSION__}`;

    this.#settings.addEventListener('click', () => {
      // Closed only once the tab exists: a popup that closes first can take the pending request with it.
      void chrome.runtime.openOptionsPage().then(() => {
        window.close();
      });
    });

    this.#openCard.addEventListener('click', () => {
      const tabId = this.#tabId;
      if (tabId === null) return;
      void sendTabMessage(tabId, { type: 'OPEN_PANEL' }).then(() => {
        // The card it opens is in the tab, behind the popup. Closing is the point of the button.
        window.close();
      });
    });

    this.#test.addEventListener('click', () => {
      void this.#testConnection();
    });

    this.#showBadgeWhenLow.addEventListener('change', () => {
      void this.#save({ showBadgeWhenLow: this.#showBadgeWhenLow.checked });
    });

    this.#highlightEnabled.addEventListener('change', () => {
      void this.#save({ highlightEnabled: this.#highlightEnabled.checked });
    });

    const [settings, state] = await Promise.all([readSettings(), this.#readState()]);
    this.#render(settings, state);
  }

  async #readState(): Promise<PopupState> {
    const tabId = await gmailTabId();
    this.#tabId = tabId;
    if (tabId === null) return { kind: 'not-gmail' };

    const response = await sendTabMessage(tabId, { type: 'GET_TAB_STATUS' });
    if (response === null || !response.ok || response.type !== 'TAB_STATUS') {
      return { kind: 'unreachable' };
    }
    return response.status;
  }

  #render(settings: Settings, state: PopupState): void {
    const head = headline(state);
    this.#chip.dataset['tone'] = head.tone;
    this.#glyph.textContent = head.glyph;
    this.#glyph.hidden = head.glyph === '';
    this.#label.textContent = head.label;
    this.#score.textContent = head.score;
    this.#score.hidden = head.score === '';
    this.#note.textContent = head.note;

    const findings = findingsLine(state);
    this.#renderFindings(state, findings);

    const cardLabel = cardButtonLabel(state);
    this.#openCard.textContent = cardLabel ?? '';
    this.#openCard.hidden = cardLabel === null;

    const ai = aiRow(settings, state);
    this.#aiLabel.textContent = ai.label;
    this.#aiDetail.textContent = ai.detail;
    this.#aiFix.textContent = ai.fix ?? '';
    this.#aiFix.hidden = ai.fix === null;
    this.#test.hidden = !ai.testable;

    this.#showBadgeWhenLow.checked = settings.showBadgeWhenLow;
    this.#highlightEnabled.checked = settings.highlightEnabled;
  }

  #renderFindings(state: PopupState, findings: string | null): void {
    if (state.kind !== 'scored' || findings === null) {
      this.#findings.replaceChildren();
      this.#more.hidden = true;
      return;
    }

    this.#findings.replaceChildren(
      // Titles are the extension's own wording, but they are built from message content, so they arrive
      // here as text and leave as text nodes — `el` has no way to do otherwise.
      ...state.headlines.map((title) => el('li', { text: title })),
    );

    const hidden = state.findings - state.headlines.length;
    this.#more.textContent =
      hidden > 0 ? `and ${String(hidden)} more — ${findings} in total` : findings;
    this.#more.hidden = false;
  }

  /**
   * The reason this popup earns its place: a model server that is running but refusing the extension's
   * origin, or one that answers with something unusable, is otherwise indistinguishable from silence.
   * The worker's error strings already name the likely cause, so they are shown verbatim.
   */
  async #testConnection(): Promise<void> {
    this.#test.disabled = true;
    this.#testResult.hidden = false;
    this.#testResult.textContent = 'Testing…';

    const response = await sendMessage({ type: 'LIST_MODELS' });
    this.#test.disabled = false;

    if (response === null) {
      this.#testResult.textContent = 'No answer from PhishLens itself. Try reopening this popup.';
      return;
    }
    if (!response.ok) {
      this.#testResult.textContent = response.error;
      return;
    }
    if (response.type !== 'MODELS') return;

    this.#testResult.textContent =
      response.models.length === 0
        ? 'Reached the server, but it reports no models loaded.'
        : `Reached the server — ${String(response.models.length)} model(s) loaded.`;
  }

  async #save(patch: Partial<Settings>): Promise<void> {
    const response = await sendMessage({ type: 'SET_SETTINGS', patch });
    if (response === null || !response.ok || response.type !== 'SETTINGS') return;
    // The content script picks the change up through `chrome.storage.onChanged`, so there is nothing to
    // tell the tab and nothing to re-render here beyond the checkbox the user just clicked.
    logger.debug('settings saved from the popup');
  }
}

async function readSettings(): Promise<Settings> {
  const response = await sendMessage({ type: 'GET_SETTINGS' });
  if (response !== null && response.ok && response.type === 'SETTINGS') return response.settings;
  return { ...DEFAULT_SETTINGS };
}

void new Popup().init();
