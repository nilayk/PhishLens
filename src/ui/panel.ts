/**
 * The explanation card: a notification-style card pinned to the bottom-right corner.
 *
 * Two properties this file exists to hold:
 *
 *  - **Observed** and **AI assessment** are separate sections and are never merged, so a user can tell
 *    "these two domains differ" (a checkable fact) from "this wording resembles phishing" (an opinion).
 *  - Every message-derived string reaches the DOM through `el({ text })`, i.e. `textContent`. No
 *    message content is ever parsed as HTML.
 *
 * All geometry is in `PANEL_CSS`; this file positions nothing. See docs/ARCHITECTURE.md §5.1.
 */
import { assessmentSignals, observedSignals } from '../analysis/engine.js';
import { CATEGORY_WEIGHTS } from '../analysis/scoring/config.js';
import type {
  AnalysisResult,
  AiMode,
  EmailMessage,
  MessagePart,
  SecuritySignal,
  SemanticStatus,
  SignalCategory,
} from '../shared/types.js';
import { createShadowHost, el } from './dom.js';
import {
  AI_DISCLAIMER,
  CATEGORY_LABELS,
  CLASSIFICATION_LABELS,
  SEVERITY_LABELS,
  UNREADABLE_LABEL,
  aiAbsenceNote,
  evidenceOf,
  isLocatable,
  messageReference,
  pendingLabel,
  unreadableNotes,
} from './format.js';
import { PANEL_CSS } from './styles.js';

const HOST_ID = 'phishlens-panel-host';

export interface PanelCallbacks {
  /** Hover/focus a finding: highlight the corresponding item in the message. */
  onFocusSignal: (signal: SecuritySignal) => void;
  onBlurSignal: () => void;
  onClose: () => void;
}

/**
 * Everything the card renders, as one value.
 *
 * Grouped rather than passed positionally because the card is repainted from three places — first
 * paint, model refinement, cache hit — and a call site that updated the result but forgot the status
 * would claim the model is unavailable while it is still running.
 */
export interface ResultView {
  kind: 'result';
  result: AnalysisResult;
  aiMode: AiMode;
  email: EmailMessage;
  semantic: SemanticStatus;
}

/**
 * The message could not be read, so there is no score to explain — only why not.
 *
 * A separate shape rather than a flag on `ResultView`, because there is no `AnalysisResult` to supply
 * and inventing a zero-scored one is precisely the failure this card exists to prevent: it would
 * classify as `low`, colour the strip green, and read as an all-clear everywhere except the paragraph
 * saying otherwise.
 */
export interface UnreadableView {
  kind: 'unreadable';
  email: EmailMessage;
  missing: readonly MessagePart[];
  /** Built by the caller, which is the layer that may touch the DOM to probe selectors. */
  diagnostic: string;
}

export type PanelView = ResultView | UnreadableView;

export class Panel {
  readonly #callbacks: PanelCallbacks;
  #host: HTMLElement | null = null;
  #root: ShadowRoot | null = null;
  #panel: HTMLElement | null = null;
  #head: HTMLElement | null = null;
  #scroll: HTMLElement | null = null;
  #open = false;

  constructor(callbacks: PanelCallbacks) {
    this.#callbacks = callbacks;
  }

  get isOpen(): boolean {
    return this.#open;
  }

  toggle(view: PanelView): void {
    if (this.#open) {
      this.close();
      return;
    }
    this.open(view);
  }

  /**
   * Shows the card, or updates it in place if already showing.
   *
   * In place because the controller paints the deterministic result and then repaints with the refined
   * one; rebuilding would replay the entrance animation and lose the reader's scroll position.
   */
  open(view: PanelView): void {
    const created = this.#host === null;
    if (created) this.#build();
    this.#paint(view);
    this.#open = true;

    if (created) {
      document.addEventListener('keydown', this.#handleKeydown, true);
      this.#root?.querySelector<HTMLButtonElement>('.close')?.focus();
    }
  }

  close(): void {
    document.removeEventListener('keydown', this.#handleKeydown, true);
    this.#callbacks.onBlurSignal();
    this.#host?.remove();
    this.#host = null;
    this.#root = null;
    this.#panel = null;
    this.#head = null;
    this.#scroll = null;
    this.#open = false;
  }

  /** Builds the empty shell once. Contents are supplied by `#paint`. */
  #build(): void {
    const { host, root } = createShadowHost(HOST_ID, PANEL_CSS);
    const head = el('div', { class: 'head' });
    const scroll = el('div', { class: 'scroll' });
    const panel = el('div', {
      class: 'panel',
      attrs: { role: 'dialog', 'aria-modal': 'false', 'aria-label': 'PhishLens security assessment' },
      children: [head, scroll],
    });

    root.append(panel);
    document.body.append(host);

    this.#host = host;
    this.#root = root;
    this.#panel = panel;
    this.#head = head;
    this.#scroll = scroll;
  }

  #paint(view: PanelView): void {
    const panel = this.#panel;
    const head = this.#head;
    const scroll = this.#scroll;
    if (panel === null || head === null || scroll === null) return;

    panel.setAttribute('data-state', view.kind === 'result' ? view.result.classification : 'unreadable');

    const offset = scroll.scrollTop;
    if (view.kind === 'result') {
      head.replaceChildren(...this.#renderHead(view.result, view.email));
      scroll.replaceChildren(
        this.#renderObserved(view.result),
        this.#renderAssessment(view),
        this.#renderFoot(view.result),
      );
    } else {
      head.replaceChildren(...this.#renderUnreadableHead(view.email));
      scroll.replaceChildren(this.#renderUnreadable(view));
    }
    scroll.scrollTop = offset;
  }

  readonly #handleKeydown = (event: KeyboardEvent): void => {
    // Capture phase so the key is seen while focus is in Gmail, but deliberately not stopped: the card
    // is not modal, and swallowing Escape would break Gmail's own dismissal of compose and dialogs.
    if (event.key === 'Escape') this.#callbacks.onClose();
  };

  // -------------------------------------------------------------------------
  // Sections
  // -------------------------------------------------------------------------

  /**
   * Score, verdict, and which message this is about.
   *
   * The message reference is load-bearing: a card fixed in the corner is not visually attached to the
   * header it describes, so without naming the message a stale assessment looks like a current one.
   */
  #renderHead(result: AnalysisResult, email: EmailMessage): Node[] {
    const state = result.classification;

    return [
      this.#renderHeadTop(),
      el('div', {
        class: 'score-row',
        children: [
          el('span', { class: 'score-value', text: String(result.score) }),
          el('span', { class: 'score-max', text: '/ 100' }),
          el('span', {
            class: 'verdict',
            text: CLASSIFICATION_LABELS[state],
            attrs: { 'data-state': state },
          }),
        ],
      }),
      el('div', {
        class: 'meter',
        attrs: { role: 'presentation' },
        children: [
          el('div', {
            class: 'meter-fill',
            attrs: { 'data-state': state },
            style: { width: `${String(result.score)}%` },
          }),
        ],
      }),
      renderReference(email),
    ];
  }

  /** Brand and close button, shared by both kinds of card. */
  #renderHeadTop(): HTMLElement {
    return el('div', {
      class: 'head-top',
      children: [
        el('span', { class: 'brand', text: 'PhishLens' }),
        el('button', {
          class: 'close',
          text: '×',
          attrs: { type: 'button', 'aria-label': 'Close' },
          on: {
            click: () => {
              this.#callbacks.onClose();
            },
          },
        }),
      ],
    });
  }

  /**
   * The head of a card with no score: the verdict slot says what did not happen instead.
   *
   * No score number and no meter, rather than a zero and an empty bar. A 0/100 with an empty meter is
   * the most reassuring thing this card could possibly display, and it would be showing it at the exact
   * moment the extension knows least about the message.
   */
  #renderUnreadableHead(email: EmailMessage): Node[] {
    return [
      this.#renderHeadTop(),
      el('div', {
        class: 'score-row',
        children: [el('span', { class: 'verdict', text: UNREADABLE_LABEL })],
      }),
      renderReference(email),
    ];
  }

  /** Deterministic findings: things that were measured. */
  #renderObserved(result: AnalysisResult): HTMLElement {
    const signals = observedSignals(result);
    const scoring = signals.filter((s) => s.score > 0);
    const notes = signals.filter((s) => s.score === 0);

    return el('section', {
      children: [
        el('h3', { class: 'section-title', text: 'Why' }),
        el('p', {
          class: 'section-note',
          text:
            scoring.length > 0
              ? 'Observed — technical checks on this message.'
              : 'Observed — technical checks found nothing of concern.',
        }),
        el('ul', {
          children:
            scoring.length > 0 || notes.length > 0
              ? [...scoring, ...notes].map((s) => this.#renderFinding(s))
              : [el('li', { children: [el('p', { class: 'empty', text: 'No findings.' })] })],
        }),
      ],
    });
  }

  /**
   * The AI section. It states plainly when no model ran, because silence would let a user assume the
   * AI approved the message, and it distinguishes "no assessment" from "not one *yet*" — the two look
   * identical and mean opposite things.
   */
  #renderAssessment(view: ResultView): HTMLElement {
    const signals = assessmentSignals(view.result);
    const note = aiAbsenceNote(view.semantic, view.aiMode);

    return el('section', {
      children: [
        el('h3', { class: 'section-title', text: 'AI assessment' }),
        /*
         * `role="status"` on the spinner row: the interesting moment for a screen-reader user is the
         * transition *out* of this state, and a polite live region announces the replacement without
         * interrupting whatever they are reading.
         */
        ...(view.semantic === 'pending'
          ? [
              el('div', {
                class: 'pending',
                attrs: { role: 'status' },
                children: [
                  el('span', { class: 'spinner', attrs: { 'aria-hidden': 'true' } }),
                  el('span', { text: pendingLabel(view.aiMode) }),
                ],
              }),
            ]
          : []),
        el('p', { class: 'ai-note', text: note ?? AI_DISCLAIMER }),
        ...(signals.length > 0
          ? [el('ul', { children: signals.map((s) => this.#renderFinding(s)) })]
          : note === null
            ? [el('p', { class: 'empty', text: 'The model returned no assessment for this message.' })]
            : []),
      ],
    });
  }

  /**
   * Why there is no score, and the report that makes it fixable.
   *
   * The report is rendered in full and selectable rather than hidden behind the copy button alone.
   * `navigator.clipboard` can refuse — an unfocused document is enough — and a user who cannot see what
   * they are about to send has no way to satisfy themselves that it holds none of their mail, which is
   * the claim the paragraph above it makes.
   */
  #renderUnreadable(view: UnreadableView): HTMLElement {
    const notes = unreadableNotes(view.missing);

    return el('section', {
      children: [
        el('h3', { class: 'section-title', text: 'Not checked' }),
        el('div', {
          class: 'notes',
          children: notes.map((note) =>
            el('p', { class: note.emphatic ? 'emphatic' : undefined, text: note.text }),
          ),
        }),
        el('details', {
          class: 'diagnostic',
          children: [
            el('summary', { text: 'Show the report' }),
            el('pre', { text: view.diagnostic }),
          ],
        }),
        el('button', {
          class: 'copy',
          text: 'Copy report',
          attrs: { type: 'button' },
          on: {
            click: (event) => {
              const button = event.currentTarget;
              if (button instanceof HTMLButtonElement) copyReport(button, view.diagnostic);
            },
          },
        }),
      ],
    });
  }

  #renderFinding(signal: SecuritySignal): HTMLElement {
    const locatable = isLocatable(signal);
    const evidence = evidenceOf(signal);

    return el('li', {
      class: 'finding',
      attrs: {
        'data-locatable': locatable,
        'data-category': signal.category,
        tabindex: locatable ? 0 : undefined,
        role: locatable ? 'button' : undefined,
      },
      on: locatable
        ? {
            mouseenter: () => {
              this.#callbacks.onFocusSignal(signal);
            },
            mouseleave: () => {
              this.#callbacks.onBlurSignal();
            },
            focus: () => {
              this.#callbacks.onFocusSignal(signal);
            },
            blur: () => {
              this.#callbacks.onBlurSignal();
            },
            click: () => {
              this.#callbacks.onFocusSignal(signal);
            },
            keydown: (event) => {
              if (event instanceof KeyboardEvent && (event.key === 'Enter' || event.key === ' ')) {
                event.preventDefault();
                this.#callbacks.onFocusSignal(signal);
              }
            },
          }
        : {},
      children: [
        el('span', {
          class: 'sev',
          text: SEVERITY_LABELS[signal.severity],
          attrs: { 'data-severity': signal.severity },
        }),
        el('div', {
          children: [
            el('p', { class: 'finding-title', text: signal.title }),
            el('p', { class: 'finding-desc', text: signal.description }),
            ...(evidence !== null
              ? [
                  el('div', {
                    class: 'evidence',
                    children: [
                      el('span', { class: 'evidence-label', text: evidence.label }),
                      // Message-derived text, rendered as a text node.
                      document.createTextNode(evidence.body),
                    ],
                  }),
                ]
              : []),
            ...(locatable
              ? [el('p', { class: 'locate-hint', text: 'Hover or press Enter to find this in the message' })]
              : []),
          ],
        }),
      ],
    });
  }

  /** Shows the arithmetic. A score whose derivation is hidden is a score nobody can argue with. */
  #renderFoot(result: AnalysisResult): HTMLElement {
    const contributing = (Object.entries(result.categoryScores) as [SignalCategory, number][])
      .filter(([, value]) => value > 0)
      .sort((a, b) => b[1] - a[1]);

    const chips = contributing.map(([category, value]) =>
      el('span', {
        text: `${CATEGORY_LABELS[category]} ${String(value)}/${String(CATEGORY_WEIGHTS[category])}`,
      }),
    );

    // The categories add up to the score unless a severe finding set a minimum, in which case they add
    // up to less. Saying so is the difference between a breakdown and arithmetic that looks broken.
    const added = contributing.reduce((sum, [, value]) => sum + value, 0);
    if (result.score > added) {
      chips.push(el('span', { class: 'floored', text: `minimum for this finding ${String(result.score)}` }));
    }

    return el('div', {
      class: 'foot',
      children: [
        chips.length > 0
          ? el('div', { class: 'breakdown', children: chips })
          : el('span', { text: 'No category contributed to the score.' }),
        el('span', {
          text: 'Advisory only. PhishLens does not block links, downloads, or replies.',
        }),
      ],
    });
  }
}

/**
 * Subject and sender, naming the message an assessment belongs to.
 *
 * Load-bearing: a card fixed in the corner is not visually attached to the header it describes, so
 * without naming the message a stale assessment looks like a current one. Both lines are
 * message-derived and so are set as text, never parsed.
 */
function renderReference(email: EmailMessage): HTMLElement {
  const reference = messageReference(email);
  return el('div', {
    class: 'ref',
    children: [
      el('div', { class: 'ref-line ref-subject', text: reference.subject, attrs: { title: reference.subject } }),
      el('div', { class: 'ref-line ref-sender', text: reference.sender, attrs: { title: reference.sender } }),
    ],
  });
}

/** Copies the report, reporting failure in the button rather than silently doing nothing. */
function copyReport(button: HTMLButtonElement, report: string): void {
  void navigator.clipboard.writeText(report).then(
    () => {
      button.textContent = 'Copied';
    },
    () => {
      button.textContent = 'Copy failed — select the report above';
      button.disabled = true;
    },
  );
}
