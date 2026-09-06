/**
 * Locates the thing in the message that a finding refers to.
 *
 * Constraint from the brief, taken seriously: *do not break Gmail's own event handlers or markup.*
 * That rules out the obvious implementation (wrap matched text in `<mark>` elements), because
 * re-parenting a node inside a Gmail-managed subtree can detach Gmail's listeners and, for anchors,
 * change what a click does. On a security tool, breaking a link's behaviour would be worse than the
 * problem being reported.
 *
 * So highlighting only ever:
 *  - adds a class token to an element that already exists, and
 *  - removes it again.
 *
 * No wrapping, no splitting text nodes, no re-parenting, no attribute rewriting, no listener changes.
 * For text evidence, the *smallest existing element* containing the text is highlighted rather than
 * the exact character range — a slightly coarser highlight in exchange for not restructuring Gmail's
 * DOM.
 */
import { collapseWhitespace } from '../shared/text.js';
import type { SecuritySignal } from '../shared/types.js';
import { normalizeDomain, parseUrl, unwrapRedirects } from '../shared/url.js';
import { HIGHLIGHT_CSS } from './styles.js';

const HIGHLIGHT_CLASS = 'phishlens-highlight';
const SUBTLE_CLASS = 'phishlens-highlight-subtle';
const STYLE_ID = 'phishlens-highlight-style';

export class Highlighter {
  #highlighted: Element[] = [];
  #styleInjected = false;

  /**
   * Injects the highlight stylesheet into the main document.
   *
   * This is the only stylesheet PhishLens adds outside a shadow root, and it is necessary because the
   * highlighted elements are Gmail's. Its selectors are namespaced under `.phishlens-` so they cannot
   * match anything Gmail styles.
   */
  #ensureStyle(): void {
    if (this.#styleInjected || document.getElementById(STYLE_ID) !== null) {
      this.#styleInjected = true;
      return;
    }
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = HIGHLIGHT_CSS;
    document.head.append(style);
    this.#styleInjected = true;
  }

  /** Highlights whatever the signal points at. Returns true if something was found. */
  show(signal: SecuritySignal, bodyElement: Element | null): boolean {
    this.clear();
    if (bodyElement === null) return false;
    this.#ensureStyle();

    const byUrl = signal.evidence?.url;
    if (byUrl !== undefined && byUrl !== '') {
      const anchors = findAnchorsForUrl(bodyElement, byUrl);
      if (anchors.length > 0) {
        for (const anchor of anchors) this.#mark(anchor, HIGHLIGHT_CLASS);
        this.#scrollTo(anchors[0]);
        return true;
      }
    }

    const byText = signal.evidence?.text;
    if (byText !== undefined && byText.length >= 12) {
      const element = findSmallestElementContaining(bodyElement, byText);
      if (element !== null) {
        this.#mark(element, SUBTLE_CLASS);
        this.#scrollTo(element);
        return true;
      }
    }
    return false;
  }

  clear(): void {
    for (const element of this.#highlighted) {
      element.classList.remove(HIGHLIGHT_CLASS, SUBTLE_CLASS);
      // Leave no trace: an empty class attribute we created should not persist.
      if (element.getAttribute('class') === '') element.removeAttribute('class');
    }
    this.#highlighted = [];
  }

  #mark(element: Element, className: string): void {
    element.classList.add(className);
    this.#highlighted.push(element);
  }

  #scrollTo(element: Element | undefined): void {
    if (element === undefined) return;
    try {
      element.scrollIntoView({ block: 'center', behavior: 'smooth' });
    } catch {
      // Older engines, or a detached node. Not worth reporting.
    }
  }

  dispose(): void {
    this.clear();
    document.getElementById(STYLE_ID)?.remove();
    this.#styleInjected = false;
  }
}

/**
 * Finds anchors whose destination matches the signal's evidence URL.
 *
 * Matched on the *unwrapped* destination and normalised host + path, not on raw string equality: the
 * evidence URL came from the same extraction pass, but Gmail rewrites hrefs and a raw comparison
 * would miss a redirect wrapper on one side and not the other.
 */
function findAnchorsForUrl(bodyElement: Element, evidenceUrl: string): HTMLAnchorElement[] {
  const target = resolveKey(evidenceUrl);
  if (target === null) return [];

  const matches: HTMLAnchorElement[] = [];
  for (const anchor of bodyElement.querySelectorAll('a[href]')) {
    if (!(anchor instanceof HTMLAnchorElement)) continue;
    const href = anchor.getAttribute('href');
    if (href === null) continue;
    if (resolveKey(href) === target) matches.push(anchor);
  }
  return matches;
}

/** `host + pathname` of the unwrapped destination, used as the comparison key. */
function resolveKey(href: string): string | null {
  const parsed = parseUrl(href);
  if (parsed === null) return null;
  const destination = unwrapRedirects(parsed).url;
  return `${normalizeDomain(destination.hostname)}${destination.pathname}`;
}

/**
 * The deepest element whose text contains the excerpt.
 *
 * Deepest rather than first so the highlight is as tight as possible without splitting text nodes.
 * The excerpt may have been whitespace-collapsed and ellipsised when it was captured as evidence, so
 * both sides are collapsed and the ellipses trimmed before comparing.
 */
function findSmallestElementContaining(root: Element, excerpt: string): Element | null {
  const needle = collapseWhitespace(excerpt.replace(/^…|…$/gu, '')).toLowerCase();
  if (needle.length < 8) return null;

  let best: Element | null = null;
  let bestLength = Number.POSITIVE_INFINITY;

  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
  let node: Node | null = root;
  while (node !== null) {
    if (node instanceof Element) {
      const content = collapseWhitespace(node.textContent).toLowerCase();
      if (content.includes(needle) && content.length < bestLength) {
        best = node;
        bestLength = content.length;
      }
    }
    node = walker.nextNode();
  }
  return best;
}
