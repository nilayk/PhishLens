/**
 * Finding the parts of a message body that are rendered but cannot be seen.
 *
 * Split from `dom-adapter.ts` because the decision "does this style attribute hide its element" is pure
 * string work and deserves to be tested directly against the forms found in real mail, rather than only
 * through a constructed DOM.
 *
 * **Inline styles only.** Gmail rewrites message CSS heavily and a content script cannot ask it what a
 * `<style>` rule resolved to, but `getComputedStyle` on every node of a large message is a layout read
 * per element and this runs on every message open. Inline `style` is where bulk mail puts this anyway,
 * because it is the only form of CSS that survives every mail client. The consequence is a rule that
 * under-reports rather than one that guesses.
 */

/** Ceiling on elements examined. A message can contain thousands of nodes. */
const MAX_ELEMENTS_SCANNED = 4000;

/** Ceiling on distinct techniques reported, so one message cannot fill the panel. */
const MAX_TECHNIQUES = 6;

/**
 * CSS declarations that take an element out of view, each paired with the name to report it by.
 *
 * Ordered most to least conclusive so the reported technique is the strongest one present.
 *
 * Every property is anchored to the start of a declaration, because CSS property names are suffixes of
 * one another and the difference is not cosmetic: `line-height:0` is on ordinary text, `min-width:0` is
 * on half the flexible layouts ever written, and an unanchored `height` pattern reads both as concealment
 * and deletes the paragraph they style.
 *
 * `font-size` is capped at 2px rather than 0: a one-pixel font is the standard preheader idiom and is
 * unreadable in the same way zero is. Offsets have to be large and negative — `left:-2px` is a nudge,
 * `left:-9999px` is a removal.
 */
const DECL = String.raw`(?:^|;)\s*`;

const HIDING_DECLARATIONS: readonly [string, RegExp][] = [
  ['display:none', new RegExp(`${DECL}display\\s*:\\s*none`, 'u')],
  ['visibility:hidden', new RegExp(`${DECL}visibility\\s*:\\s*(hidden|collapse)`, 'u')],
  ['opacity:0', new RegExp(`${DECL}opacity\\s*:\\s*0*(\\.0+)?\\s*(;|$)`, 'u')],
  // Zero at any unit, or one to two *pixels*. Not `1em`, which is ordinary body text.
  ['font-size:0', new RegExp(`${DECL}font-size\\s*:\\s*(0(\\.\\d+)?\\s*[a-z%]*|[0-2](\\.\\d+)?\\s*(px|pt))\\b`, 'u')],
  ['height:0', new RegExp(`${DECL}(max-)?height\\s*:\\s*0(\\.\\d+)?\\s*[a-z%]*\\s*(;|$)`, 'u')],
  ['width:0', new RegExp(`${DECL}(max-)?width\\s*:\\s*0(\\.\\d+)?\\s*[a-z%]*\\s*(;|$)`, 'u')],
  ['clipped', new RegExp(`${DECL}(clip\\s*:\\s*rect\\(\\s*0|clip-path\\s*:\\s*inset\\(\\s*(100%|50%))`, 'u')],
  [
    'moved off screen',
    new RegExp(`${DECL}(text-indent|left|right|top|margin-left|margin-top)\\s*:\\s*-\\d{3,}`, 'u'),
  ],
];

/**
 * The strongest hiding technique a style attribute applies, or `null` when it applies none.
 *
 * Exported for tests. Takes the attribute as written; whitespace and case vary freely in real mail.
 */
export function hidingTechnique(styleAttribute: string): string | null {
  const style = styleAttribute.toLowerCase();
  for (const [name, pattern] of HIDING_DECLARATIONS) {
    if (pattern.test(style)) return name;
  }
  return null;
}

/** Letters and digits only: invisible padding (`&nbsp;`, `&zwnj;`) is not content being concealed. */
export function countContentChars(text: string): number {
  return (text.match(/[\p{L}\p{N}]/gu) ?? []).length;
}

export interface HiddenScan {
  /** Elements whose subtrees are hidden. Outermost only — a hidden child of a hidden parent is not extra. */
  roots: Element[];
  techniques: string[];
}

/**
 * Every hidden subtree in an element, with the techniques used.
 *
 * Nested hidden elements collapse into their outermost ancestor. Counting them separately would report
 * a hidden `<div>` of ten hidden `<span>`s as eleven findings and count its text eleven times.
 *
 * `aria-hidden="true"` is deliberately not treated as hiding. It instructs screen readers to skip an
 * element that is *on screen* — decorative arrows, icons, spacer cells — and mail uses it that way
 * constantly. Since a caller removes what this returns from the visible body, honouring it would delete
 * text the reader can see, which both loses findings and hands an attacker a one-attribute way to keep
 * wording out of the analysis while still showing it.
 */
export function findHiddenSubtrees(root: Element): HiddenScan {
  const roots: Element[] = [];
  const techniques = new Set<string>();
  let scanned = 0;

  for (const element of root.querySelectorAll('[style],[hidden]')) {
    if (scanned >= MAX_ELEMENTS_SCANNED) break;
    scanned += 1;

    // Document order, so an ancestor is always seen before its descendants.
    if (roots.some((found) => found.contains(element))) continue;

    const technique =
      hidingTechnique(element.getAttribute('style') ?? '') ??
      (element.hasAttribute('hidden') ? 'hidden attribute' : null);
    if (technique === null) continue;

    roots.push(element);
    if (techniques.size < MAX_TECHNIQUES) techniques.add(technique);
  }

  return { roots, techniques: [...techniques] };
}
