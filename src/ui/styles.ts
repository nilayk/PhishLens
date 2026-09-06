/**
 * Static stylesheets for the injected UI.
 *
 * Authored here, never derived from message content. The visual language is deliberately restrained:
 * a security tool that shouts is one users learn to dismiss, and the difference between "caution" and
 * "high risk" has to survive being seen a hundred times a day. Colour is a secondary cue behind the
 * text label, so the states remain distinguishable to colour-blind users and in high-contrast modes.
 */

export const BADGE_CSS = `
/*
 * The host sits in the header's right-hand cluster, beside the timestamp. It is inline-block with a
 * left margin rather than floated or absolutely positioned, so it occupies space Gmail has already
 * laid out instead of overlapping something.
 */
:host { all: initial; display: inline-block; vertical-align: middle; margin-left: 8px; }
* { box-sizing: border-box; }

.badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-family: 'Google Sans', Roboto, system-ui, -apple-system, 'Segoe UI', sans-serif;
  /* A shade smaller than the body badge would be: it shares a line with Gmail's own header controls. */
  font-size: 11px;
  font-weight: 500;
  line-height: 1;
  padding: 4px 8px;
  border-radius: 999px;
  border: 1px solid transparent;
  cursor: pointer;
  white-space: nowrap;
  transition: box-shadow 120ms ease, background-color 120ms ease;
  -webkit-font-smoothing: antialiased;
}
.badge:hover { box-shadow: 0 1px 4px rgb(0 0 0 / 18%); }
.badge:focus-visible { outline: 2px solid #1a73e8; outline-offset: 2px; }

.glyph { font-size: 11px; line-height: 1; }
.score { opacity: 0.75; font-variant-numeric: tabular-nums; }
.sep { opacity: 0.4; }

.badge[data-state="low"]        { background: #e6f4ea; color: #137333; border-color: #ceead6; }
.badge[data-state="caution"]    { background: #fef7e0; color: #8a5300; border-color: #fde293; }
.badge[data-state="suspicious"] { background: #fce8e6; color: #b3261e; border-color: #f9d2cf; }
.badge[data-state="high-risk"]  { background: #b3261e; color: #ffffff; border-color: #8c1d18; }
.badge[data-state="pending"]    { background: #f1f3f4; color: #5f6368; border-color: #e0e3e5; cursor: default; }

@media (prefers-color-scheme: dark) {
  .badge[data-state="low"]        { background: #1e3a28; color: #81c995; border-color: #2d5a3d; }
  .badge[data-state="caution"]    { background: #3d3122; color: #fdd663; border-color: #5c4a2e; }
  .badge[data-state="suspicious"] { background: #452420; color: #f28b82; border-color: #6b322c; }
  .badge[data-state="high-risk"]  { background: #b3261e; color: #ffffff; border-color: #d93025; }
  .badge[data-state="pending"]    { background: #2d2e30; color: #9aa0a6; border-color: #3c4043; }
}

@media (prefers-reduced-motion: reduce) {
  .badge { transition: none; }
}
`;

/**
 * The advisory card.
 *
 * Pinned to the bottom-right of the viewport rather than anchored to the badge. Anchoring meant the
 * card was positioned from the badge's viewport rect, so scrolling the message carried it off screen
 * — the explanation disappeared exactly when the user scrolled down to check the thing it described.
 * A fixed corner has no such coupling: it needs no scroll listener, no reflow on resize, and it does
 * not fight Gmail's own scroll containers for space.
 *
 * It is deliberately *not* modal. There is no backdrop, so Gmail stays fully interactive while the
 * card is open — a security advisory the user must dismiss before they can look at the message is an
 * advisory that gets dismissed unread.
 */
export const PANEL_CSS = `
:host { all: initial; }
* { box-sizing: border-box; }

.panel {
  position: fixed;
  right: 16px;
  bottom: 16px;
  z-index: 2147483001;
  display: flex;
  flex-direction: column;
  width: 380px;
  max-width: calc(100vw - 32px);
  max-height: min(72vh, 620px);
  /* The state colour lives in this 4px strip, so the card itself stays neutral and legible. */
  padding-left: 4px;
  overflow: hidden;
  background: #ffffff;
  color: #202124;
  border: 1px solid #dadce0;
  border-radius: 12px;
  box-shadow: 0 6px 24px rgb(0 0 0 / 18%), 0 2px 6px rgb(0 0 0 / 8%);
  font-family: 'Google Sans', Roboto, system-ui, -apple-system, 'Segoe UI', sans-serif;
  font-size: 13px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

.panel::before {
  content: '';
  position: absolute;
  inset: 0 auto 0 0;
  width: 4px;
  background: #dadce0;
}
.panel[data-state="low"]::before { background: #34a853; }
.panel[data-state="caution"]::before { background: #f9ab00; }
.panel[data-state="suspicious"]::before { background: #ea4335; }
.panel[data-state="high-risk"]::before { background: #b3261e; }

/* Head is fixed; only the findings scroll. */
.head { flex: none; padding: 12px 16px; border-bottom: 1px solid #f1f3f4; }
.scroll { flex: 1 1 auto; overflow-y: auto; overscroll-behavior: contain; }

/*
 * Scrollbar, restyled to belong to the card. Chromium's default is a 15px grey channel with a hard
 * inner edge and arrow buttons, which inside a 380px rounded card reads as a seam pinned to the right
 * side — and it runs straight through the rounded bottom corner, because the footer scrolls with the
 * findings.
 *
 * Drawn instead as an overlay over the card's own surface: transparent track, and a thin thumb inset
 * from the edge so it floats clear of both the border and the corner radius. The inset comes from a
 * transparent border with \`background-clip: padding-box\` — scrollbar parts do not honour margin or
 * padding, so the border is the only way to get breathing room around the thumb. For the same reason
 * the hover rule sets \`background-color\`, not the \`background\` shorthand, which would reset the clip
 * back to \`border-box\` and refill the inset.
 *
 * Uses the \`-webkit-\` pseudo-elements rather than the standard \`scrollbar-width\`/\`scrollbar-color\`
 * pair. The two are mutually exclusive in Chromium — declaring either standard property makes it
 * ignore the pseudo-elements — and only the pseudo-elements can inset the thumb. Chrome-only support is
 * not a constraint for a Chrome extension.
 *
 * The thumb is quiet but always visible while the content overflows. It is the only cue that findings
 * continue below the fold, and on a security advisory a hidden cue is a finding the user never reads;
 * hover-to-reveal was rejected for that reason.
 */
.scroll::-webkit-scrollbar { width: 10px; }
.scroll::-webkit-scrollbar-track { background: transparent; }
.scroll::-webkit-scrollbar-thumb {
  background-color: #dadce0;
  background-clip: padding-box;
  border: 3px solid transparent;
  border-radius: 8px;
}
.scroll::-webkit-scrollbar-thumb:hover { background-color: #bdc1c6; }
.scroll::-webkit-scrollbar-button, .scroll::-webkit-scrollbar-corner { display: none; }

.head-top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.brand { font-size: 10px; font-weight: 500; letter-spacing: 0.08em; text-transform: uppercase; color: #80868b; }

.score-row { display: flex; align-items: baseline; gap: 6px; margin-top: 6px; }
.score-value { font-size: 26px; font-weight: 500; letter-spacing: -0.01em; font-variant-numeric: tabular-nums; }
.score-max { font-size: 13px; color: #5f6368; }
.verdict { margin-left: auto; font-size: 13px; font-weight: 500; }

/*
 * Which message this is about. The card no longer sits beside the header it describes, so it has to
 * say — otherwise a stale card in the corner is indistinguishable from a current one.
 */
.ref { margin-top: 10px; display: grid; gap: 1px; }
.ref-line { font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ref-subject { color: #3c4043; font-weight: 500; }
.ref-sender { color: #80868b; }

.verdict[data-state="low"] { color: #137333; }
.verdict[data-state="caution"] { color: #8a5300; }
.verdict[data-state="suspicious"] { color: #b3261e; }
.verdict[data-state="high-risk"] { color: #b3261e; }

.close {
  flex: none;
  border: none;
  background: transparent;
  color: #5f6368;
  font-size: 18px;
  line-height: 1;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  cursor: pointer;
}
.close:hover { background: #f1f3f4; }
.close:focus-visible { outline: 2px solid #1a73e8; outline-offset: 1px; }

.meter { height: 4px; border-radius: 2px; background: #f1f3f4; overflow: hidden; margin-top: 8px; }
.meter-fill { height: 100%; border-radius: 2px; }
.meter-fill[data-state="low"] { background: #34a853; }
.meter-fill[data-state="caution"] { background: #f9ab00; }
.meter-fill[data-state="suspicious"] { background: #ea4335; }
.meter-fill[data-state="high-risk"] { background: #b3261e; }

section { padding: 12px 16px; border-bottom: 1px solid #f1f3f4; }
section:last-of-type { border-bottom: none; }

.section-title {
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: #5f6368;
  margin: 0 0 4px;
}
.section-note { font-size: 11px; color: #80868b; margin: 0 0 10px; }

ul { list-style: none; margin: 0; padding: 0; }

li.finding {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 8px;
  padding: 8px;
  margin: 0 -8px;
  border-radius: 8px;
}
li.finding[data-locatable="true"] { cursor: pointer; }
li.finding[data-locatable="true"]:hover { background: #f8f9fa; }
li.finding:focus-visible { outline: 2px solid #1a73e8; outline-offset: -2px; }

.sev {
  flex: none;
  align-self: start;
  margin-top: 1px;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.05em;
  padding: 3px 5px;
  border-radius: 4px;
  min-width: 52px;
  text-align: center;
}
.sev[data-severity="critical"] { background: #b3261e; color: #fff; }
.sev[data-severity="high"] { background: #fce8e6; color: #b3261e; }
.sev[data-severity="medium"] { background: #fef7e0; color: #8a5300; }
.sev[data-severity="low"] { background: #e8f0fe; color: #1967d2; }
.sev[data-severity="info"] { background: #f1f3f4; color: #5f6368; }

.finding-title { font-weight: 500; margin: 0; }
.finding-desc { margin: 3px 0 0; color: #3c4043; }

.evidence {
  margin: 6px 0 0;
  padding: 6px 8px;
  background: #f8f9fa;
  border-left: 2px solid #dadce0;
  border-radius: 0 4px 4px 0;
  font-family: 'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11px;
  color: #3c4043;
  word-break: break-all;
  white-space: pre-wrap;
}
.evidence-label { display: block; font-family: inherit; font-size: 10px; color: #80868b; margin-bottom: 2px; }

.locate-hint { margin-top: 4px; font-size: 11px; color: #1a73e8; }

.ai-note {
  margin: 0 0 8px;
  padding: 8px 10px;
  background: #f8f9fa;
  border-radius: 6px;
  font-size: 11px;
  color: #5f6368;
}

/*
 * Waiting on the model. Deliberately understated — the deterministic verdict is already on screen and
 * complete, so this is a footnote about a refinement, not a "loading" screen for the card.
 */
.pending { display: flex; align-items: center; gap: 8px; margin: 2px 0 8px; color: #3c4043; }
.spinner {
  flex: none;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  border: 2px solid #dadce0;
  border-top-color: #1a73e8;
}
/*
 * The ring is static without the animation, which still reads as an indicator next to the label; the
 * label is what actually carries the meaning, so nothing is lost when motion is not wanted.
 */
@media (prefers-reduced-motion: no-preference) {
  .spinner { animation: phishlens-spin 800ms linear infinite; }
  @keyframes phishlens-spin { to { transform: rotate(360deg); } }
}

.empty { color: #5f6368; margin: 0; }

.foot {
  padding: 10px 16px 12px;
  font-size: 11px;
  color: #80868b;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.foot a { color: #1a73e8; text-decoration: none; }
.foot a:hover { text-decoration: underline; }

.breakdown { display: flex; flex-wrap: wrap; gap: 4px 10px; }
.breakdown span { font-variant-numeric: tabular-nums; }
/* Reads as a note on the sum rather than another term in it. */
.breakdown .floored { font-style: italic; opacity: 0.85; }

/*
 * Entrance. Notification-like rather than decorative: it rises 8px and fades in once, which is what
 * makes the corner card read as "this just appeared" instead of "this has always been here".
 * Re-renders (the deterministic result being refined by the model) reuse the existing element, so the
 * animation does not replay and the scroll position is kept.
 */
@media (prefers-reduced-motion: no-preference) {
  .panel { animation: phishlens-rise 140ms cubic-bezier(0.2, 0, 0, 1); }
  @keyframes phishlens-rise {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: none; }
  }
}

/* Narrow windows: span the width rather than crowding one corner. */
@media (max-width: 480px) {
  .panel {
    left: 12px;
    right: 12px;
    bottom: 12px;
    width: auto;
    max-width: none;
    max-height: 78vh;
  }
}

@media (prefers-color-scheme: dark) {
  .panel { background: #292a2d; color: #e8eaed; border-color: #3c4043; }
  .panel::before { background: #5f6368; }
  .head { border-bottom-color: #3c4043; }
  section { border-bottom-color: #3c4043; }
  .score-max, .section-title, .section-note, .foot, .empty, .brand, .ref-sender { color: #9aa0a6; }
  .ref-subject { color: #e8eaed; }
  .finding-desc { color: #bdc1c6; }
  .close { color: #9aa0a6; }
  .close:hover { background: #3c4043; }
  .meter { background: #3c4043; }
  .scroll::-webkit-scrollbar-thumb { background-color: #5f6368; }
  .scroll::-webkit-scrollbar-thumb:hover { background-color: #80868b; }
  li.finding[data-locatable="true"]:hover { background: #35363a; }
  .evidence, .ai-note { background: #202124; border-left-color: #5f6368; color: #bdc1c6; }
  .pending { color: #e8eaed; }
  .spinner { border-color: #3c4043; border-top-color: #8ab4f8; }
  .verdict[data-state="low"] { color: #81c995; }
  .verdict[data-state="caution"] { color: #fdd663; }
  .verdict[data-state="suspicious"], .verdict[data-state="high-risk"] { color: #f28b82; }
  .sev[data-severity="high"] { background: #452420; color: #f28b82; }
  .sev[data-severity="medium"] { background: #3d3122; color: #fdd663; }
  .sev[data-severity="low"] { background: #1f3047; color: #8ab4f8; }
  .sev[data-severity="info"] { background: #3c4043; color: #9aa0a6; }
}
`;

/**
 * Highlight styles, injected into the *main* document rather than a shadow root, because the elements
 * being highlighted are Gmail's own.
 *
 * The highlight is applied by adding a single class token to an existing element and removing it
 * afterwards. Nothing is wrapped, re-parented, or replaced, so Gmail's event handlers on those
 * elements are untouched — which is the constraint the brief sets. `!important` is used because Gmail's
 * own link styles are specific, and losing the highlight would make the feature silently useless.
 */
export const HIGHLIGHT_CSS = `
.phishlens-highlight {
  outline: 2px solid #ea4335 !important;
  outline-offset: 2px !important;
  background-color: rgb(234 67 53 / 12%) !important;
  border-radius: 2px !important;
  scroll-margin: 120px;
}
.phishlens-highlight-subtle {
  outline: 2px dashed #f9ab00 !important;
  outline-offset: 2px !important;
  scroll-margin: 120px;
}
@media (prefers-reduced-motion: no-preference) {
  .phishlens-highlight, .phishlens-highlight-subtle {
    transition: outline-color 120ms ease, background-color 120ms ease;
  }
}
`;
