/**
 * Markers on inbox rows, for the decision made before a message is opened.
 *
 * What a row can support is set out in `analysis/triage.ts`: a warning about the sender, or nothing.
 * This file is the DOM half — finding rows, reading the sender line, and putting a mark beside it — and
 * it is written around the two things that make a list different from a conversation view.
 *
 * **Gmail recycles rows.** Scrolling and refreshing reuse the same `tr` elements with different mail in
 * them, so a mark can end up beside a message it was not computed for. Each row therefore records the
 * sender it was marked for, and a row whose sender has changed is re-evaluated rather than left alone.
 *
 * **A list re-renders constantly.** Every pass is debounced, bounded to the rows actually on screen, and
 * skips rows whose sender is unchanged, so the steady state costs one attribute read per row.
 *
 * The mark itself is inline-styled rather than given a stylesheet or a shadow root. Both alternatives
 * were tried: a stylesheet in the page is a global we do not want, and a shadow host per row is dozens
 * of extra roots for one glyph. Inline properties beat Gmail's own CSS without either.
 */
import { triageSender, type TriageSeverity, type TriageVerdict } from '../analysis/triage.js';
import { queryFirst, SELECTORS } from '../gmail/selectors.js';
import { logger } from '../shared/logger.js';
import { el } from '../ui/dom.js';

/** Marks the row was computed for, so a recycled row is re-evaluated rather than trusted. */
const MARKED_FOR = 'data-phishlens-row';
const MARK_CLASS = 'phishlens-row-mark';

/**
 * Bounds one pass. Gmail renders about 50 rows per page and never thousands, so this is a guard against
 * a markup change matching something enormous rather than a real limit on inbox size.
 */
const MAX_ROWS = 120;

/** Quiet period after list churn. Longer than the message observer's: nothing here is time-critical. */
const DEBOUNCE_MS = 300;

/** The badge's glyphs, so a mark and the badge it precedes are recognisably the same vocabulary. */
const GLYPHS: Readonly<Record<TriageSeverity, string>> = {
  high: '⚠',
  critical: '⛔',
};

const COLOURS: Readonly<Record<TriageSeverity, string>> = {
  high: '#b3261e',
  critical: '#b3261e',
};

export class ListMarks {
  #observer: MutationObserver | null = null;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #root: Element | null = null;
  /**
   * How to read the signed-in address, so the lookalike-of-your-own-domain check can run.
   *
   * A callback rather than a string because marking starts at `document_idle`, when Gmail has often not
   * rendered its account chrome yet. Reading it once at that moment gives an empty address for the life of
   * the tab, silently losing the most valuable verdict a row can carry — a domain imitating the reader's
   * own employer.
   */
  #readAccount: () => string = () => '';
  /** Cached once found. It cannot change without a reload, and the read walks Gmail's chrome. */
  #recipientEmail = '';

  start(root: Element, readAccount: () => string): void {
    this.stop();
    this.#root = root;
    this.#readAccount = readAccount;

    this.#observer = new MutationObserver(() => {
      this.#schedule();
    });
    this.#observer.observe(root, { childList: true, subtree: true });
    this.#schedule();
    logger.debug('list marks attached');
  }

  stop(): void {
    this.#observer?.disconnect();
    this.#observer = null;
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = null;
    this.#clearAll();
    this.#root = null;
  }

  #schedule(): void {
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = setTimeout(() => {
      this.#timer = null;
      this.#scan();
    }, DEBOUNCE_MS);
  }

  #scan(): void {
    const root = this.#root;
    if (root === null) return;

    const recipient = this.#recipient();

    let marked = 0;
    for (const row of rowsIn(root)) {
      const sender = readSender(row);
      // The key includes the display name: the same address with a different name is a different claim,
      // and the impersonation rules are largely about the name.
      const key = `${sender.senderEmail}|${sender.senderName}`;
      if (row.getAttribute(MARKED_FOR) === key) continue;

      removeMark(row);
      row.setAttribute(MARKED_FOR, key);

      const verdict = sender.senderEmail === '' ? null : triageSender({ ...sender, ...recipient });
      if (verdict === null) continue;
      if (addMark(row, verdict)) marked += 1;
    }

    if (marked > 0) logger.debug('list rows marked', { marked });
  }

  /** Resolved once per pass, and retried on later passes for as long as Gmail has not exposed it. */
  #recipient(): { recipientEmail?: string } {
    if (this.#recipientEmail === '') this.#recipientEmail = this.#readAccount();
    return this.#recipientEmail === '' ? {} : { recipientEmail: this.#recipientEmail };
  }

  #clearAll(): void {
    for (const mark of document.querySelectorAll(`.${MARK_CLASS}`)) mark.remove();
    for (const row of document.querySelectorAll(`[${MARKED_FOR}]`)) row.removeAttribute(MARKED_FOR);
  }
}

function rowsIn(root: Element): Element[] {
  for (const selector of SELECTORS.listRow) {
    try {
      const found = root.querySelectorAll(selector);
      if (found.length > 0) return [...found].slice(0, MAX_ROWS);
    } catch {
      // An invalid candidate is not a match, exactly as in `queryFirst`.
    }
  }
  return [];
}

/**
 * The sender line as the row presents it.
 *
 * `[email]` is what makes triage possible from a list at all: Gmail puts the real address in that
 * attribute even though the row displays only a name. Without it there is no address, so there is no
 * verdict — which is the honest outcome rather than a guess from a display name.
 */
function readSender(row: Element): { senderName: string; senderEmail: string } {
  const element = queryFirst(row, SELECTORS.listSender);
  if (element === null) return { senderName: '', senderEmail: '' };

  return {
    senderEmail: element.getAttribute('email')?.trim() ?? '',
    // `name` carries the full display name; the row's text is often truncated to fit the column, and a
    // truncated name would make the impersonation checks see a different string than the card does.
    senderName: (element.getAttribute('name') ?? element.textContent).trim(),
  };
}

function removeMark(row: Element): void {
  row.querySelector(`.${MARK_CLASS}`)?.remove();
}

/** Returns whether the mark was placed; a row whose cells cannot be found is left alone. */
function addMark(row: Element, verdict: TriageVerdict): boolean {
  const cell = queryFirst(row, SELECTORS.listSubjectCell);
  if (cell === null) return false;

  const mark = el('span', {
    class: MARK_CLASS,
    text: GLYPHS[verdict.severity],
    attrs: {
      // The finding's own wording, as the tooltip. It comes from a message, so it arrives as text and is
      // set as an attribute value — never parsed.
      title: `PhishLens: ${verdict.title}. This message has not been opened or fully checked.`,
      'aria-label': `PhishLens warning: ${verdict.title}`,
      'data-phishlens-severity': verdict.severity,
      role: 'img',
    },
    style: {
      'margin-right': '6px',
      'font-size': '11px',
      'font-weight': '700',
      'line-height': '1',
      color: COLOURS[verdict.severity],
      // The row is a flex/table cell whose children Gmail sizes; an inline-block that cannot shrink
      // keeps the glyph from being squeezed to nothing in a narrow window.
      display: 'inline-block',
      'flex-shrink': '0',
      cursor: 'help',
    },
  });

  cell.prepend(mark);
  return true;
}
