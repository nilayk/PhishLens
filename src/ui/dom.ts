/**
 * Safe element construction.
 *
 * The single most important property of the UI layer: **attacker-controlled email content is never
 * parsed as HTML.** Rather than relying on remembering that, this helper makes it structurally true —
 * `el()` has no parameter that accepts markup, and text is only ever assigned via `textContent`.
 * ESLint additionally bans `innerHTML`, `outerHTML`, and `insertAdjacentHTML` project-wide.
 *
 * A signal's title, description, and evidence all originate in an email. They arrive here as strings
 * and leave as text nodes.
 */

export type Attrs = Record<string, string | number | boolean | undefined>;

export interface ElOptions {
  /** Class names. */
  class?: string;
  /** Text content. Assigned with `textContent`; never interpreted as markup. */
  text?: string;
  attrs?: Attrs;
  /** Inline styles, set property-by-property rather than via a style string. */
  style?: Partial<Record<string, string>>;
  children?: (Node | null | undefined | false)[];
  on?: Partial<Record<string, (event: Event) => void>>;
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  options: ElOptions = {},
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);

  if (options.class !== undefined) node.className = options.class;
  if (options.text !== undefined) node.textContent = options.text;

  if (options.attrs !== undefined) {
    for (const [name, value] of Object.entries(options.attrs)) {
      if (value === undefined || value === false) continue;
      // `setAttribute` cannot introduce script here because no attribute name we pass is an event
      // handler, and callers never derive attribute names from email content.
      node.setAttribute(name, value === true ? '' : String(value));
    }
  }

  if (options.style !== undefined) {
    for (const [property, value] of Object.entries(options.style)) {
      if (value !== undefined) node.style.setProperty(property, value);
    }
  }

  if (options.children !== undefined) {
    for (const child of options.children) {
      if (child !== null && child !== undefined && child !== false) node.append(child);
    }
  }

  if (options.on !== undefined) {
    for (const [type, handler] of Object.entries(options.on)) {
      if (handler !== undefined) node.addEventListener(type, handler);
    }
  }

  return node;
}

export function text(value: string): Text {
  return document.createTextNode(value);
}

/** Removes every child of a node without touching `innerHTML`. */
export function clear(node: Node): void {
  while (node.firstChild !== null) node.removeChild(node.firstChild);
}

/**
 * Creates a shadow-DOM host.
 *
 * Both the badge and the panel live inside a shadow root so that Gmail's stylesheet cannot distort
 * them and ours cannot distort Gmail. `mode: 'open'` rather than `'closed'` deliberately: a security
 * tool should be inspectable by the user in DevTools, and closed mode buys no real protection since
 * the page could not reach into our isolated world anyway.
 */
export function createShadowHost(id: string, css: string): { host: HTMLElement; root: ShadowRoot } {
  const host = el('div', { attrs: { id, 'data-phishlens': 'host' } });
  const root = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  // Static CSS authored in this repository, never derived from email content.
  style.textContent = css;
  root.append(style);
  return { host, root };
}
