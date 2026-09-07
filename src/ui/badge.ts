/**
 * The in-Gmail risk badge.
 *
 * Injection footprint: one element appended into the message header's right-hand cluster, with its
 * contents in a shadow root. Gmail's own nodes are never modified, reordered, or re-styled, and no
 * listener is added to anything Gmail owns.
 */
import type { AnalysisResult, Classification } from '../shared/types.js';
import { createShadowHost, el } from './dom.js';
import { BADGE_CSS } from './styles.js';
import {
  CLASSIFICATION_GLYPHS,
  CLASSIFICATION_LABELS,
  UNREADABLE_ARIA,
  UNREADABLE_GLYPH,
  UNREADABLE_LABEL,
  ariaLabel,
} from './format.js';

const HOST_ID = 'phishlens-badge-host';

export interface BadgeCallbacks {
  onActivate: () => void;
}

export class Badge {
  readonly #callbacks: BadgeCallbacks;
  #host: HTMLElement | null = null;
  #button: HTMLButtonElement | null = null;

  constructor(callbacks: BadgeCallbacks) {
    this.#callbacks = callbacks;
  }

  /** Attaches (or moves) the badge next to the given header element. */
  attach(headerElement: Element): void {
    if (this.#host === null) this.#build();
    const host = this.#host;
    if (host === null) return;

    // Gmail re-renders headers; re-appending moves our existing node rather than creating a second.
    if (host.parentElement !== headerElement) headerElement.append(host);
  }

  #build(): void {
    const { host, root } = createShadowHost(HOST_ID, BADGE_CSS);
    const button = el('button', {
      class: 'badge',
      attrs: { type: 'button', 'data-state': 'pending', 'aria-live': 'polite' },
      on: {
        click: (event) => {
          event.preventDefault();
          event.stopPropagation();
          this.#callbacks.onActivate();
        },
        // Gmail's header row has its own click handling (expand/collapse). Stopping propagation on
        // mousedown too keeps activating the badge from also toggling the message.
        mousedown: (event) => {
          event.stopPropagation();
        },
      },
    });

    root.append(button);
    this.#host = host;
    this.#button = button;
    this.setPending();
  }

  setPending(): void {
    const button = this.#button;
    if (button === null) return;
    this.#render(button, 'pending', 'Checking…', '');
    button.setAttribute('aria-label', 'PhishLens is analysing this message.');
    button.disabled = true;
  }

  /**
   * The message could not be read well enough to score. Clickable, unlike `pending`: the card is where
   * the explanation and the diagnostic live, and this state is the one a user needs to act on.
   */
  setUnreadable(): void {
    const button = this.#button;
    if (button === null) return;
    this.#render(button, 'unreadable', UNREADABLE_LABEL, '', UNREADABLE_GLYPH);
    button.setAttribute('aria-label', UNREADABLE_ARIA);
    button.disabled = false;
  }

  setResult(result: AnalysisResult): void {
    const button = this.#button;
    if (button === null) return;
    const state = result.classification;
    this.#render(
      button,
      state,
      CLASSIFICATION_LABELS[state],
      `${String(result.score)}/100`,
      CLASSIFICATION_GLYPHS[state],
    );
    button.setAttribute(
      'aria-label',
      ariaLabel(state, result.score, result.signals.filter((s) => s.score > 0).length),
    );
    button.disabled = false;
  }

  /** Rebuilds the badge's contents from text nodes only. */
  #render(
    button: HTMLButtonElement,
    state: Classification | 'pending' | 'unreadable',
    label: string,
    score: string,
    glyph = '',
  ): void {
    button.setAttribute('data-state', state);
    button.replaceChildren(
      ...(glyph !== '' ? [el('span', { class: 'glyph', text: glyph, attrs: { 'aria-hidden': 'true' } })] : []),
      el('span', { class: 'label', text: label }),
      ...(score !== ''
        ? [
            el('span', { class: 'sep', text: '·', attrs: { 'aria-hidden': 'true' } }),
            el('span', { class: 'score', text: score }),
          ]
        : []),
    );
  }

  isAttached(): boolean {
    return this.#host?.isConnected === true;
  }

  remove(): void {
    this.#host?.remove();
    this.#host = null;
    this.#button = null;
  }
}
