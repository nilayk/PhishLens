/**
 * UI harness: the real `Badge` and `Panel`, driven by the real engine, over the `test/fixtures/` corpus.
 *
 * Why this exists: the components only have meaning inside a mail message, so there is nothing a dev
 * server can preview (docs/ARCHITECTURE.md §1.1) and every UI state otherwise has to be reached by
 * finding an email that produces it. Here each state is a URL.
 *
 * Every control is also a query parameter, which is what lets `scripts/screenshots.mjs` regenerate
 * `docs/assets/` without driving the widgets: navigate, wait, capture.
 *
 *   ?fixture=microsoft-phish&semantic=ready&card=1&view=full&bare=1&missing=none
 *
 * Development-only. Not bundled into the extension, and it never reaches a network or a real message.
 */
import { analyzeDeterministic, analyze, withSemanticStatus } from '../src/analysis/engine.js';
import { ListMarks } from '../src/content/list-marks.js';
import { isScorable } from '../src/gmail/adapter.js';
import { formatDiagnostic } from '../src/gmail/diagnostics.js';
import type {
  AiMode,
  AnalysisResult,
  Classification,
  EmailMessage,
  MessagePart,
  SemanticAnalysis,
  SemanticAnalyzer,
  SemanticStatus,
} from '../src/shared/types.js';
import { trustEntryFor, type TrustState } from '../src/shared/trust.js';
import { Badge } from '../src/ui/badge.js';
import { el } from '../src/ui/dom.js';
import { Panel, type PanelView } from '../src/ui/panel.js';
import { toFixture, type Fixture, type RawFixture } from '../test/fixtures/convert.js';

/** Injected by scripts/harness.mjs, so adding a fixture file needs no change here. */
declare const __PHISHLENS_FIXTURES__: string;

type View = 'full' | 'badges' | 'card' | 'list';

const SEMANTIC_STATES: readonly SemanticStatus[] = [
  'ready',
  'pending',
  'unavailable',
  'no-output',
  'error',
  'cancelled',
  'off',
];

const VIEWS: readonly View[] = ['full', 'badges', 'card', 'list'];

/**
 * The AI section names whichever analyzer ran, so each mode is its own state. Without this the wording
 * for a model server or the cloud path could only be seen by configuring one.
 */
const AI_MODES: readonly AiMode[] = ['local', 'server', 'cloud', 'off'];

/** Ascending, so `view=badges` reads from safest to worst. */
const BANDS: readonly Classification[] = ['low', 'caution', 'suspicious', 'high-risk'];

/**
 * Which parts of the message the adapter is pretending it could not read.
 *
 * The only way to see the "not checked" state otherwise is to break a selector against live Gmail. Both
 * outcomes are here on purpose: `subject` is not load-bearing, so it must still produce an ordinary
 * scored card, and seeing that is what distinguishes a working rule from one that withholds a score
 * whenever anything at all is absent.
 */
const MISSING_STATES: readonly string[] = ['none', 'sender', 'subject'];

/**
 * The trust control's states, which the card renders but the engine decides.
 *
 * Listed rather than derived because each depends on a combination the fixtures cannot all produce:
 * `trusted` needs the sender in a list held in `chrome.storage`, and `unproven` needs that plus a message
 * whose origin Gmail did not confirm. The card's own wording is what is being previewed here.
 */
const TRUST_STATES: readonly string[] = ['none', 'offer', 'trusted', 'unproven'];

function trustFor(kind: string, email: EmailMessage): TrustState {
  if (kind === 'none') return { kind: 'none' };
  const entry = trustEntryFor(email.senderEmail ?? '') ?? 'northwind-supply.example';
  return { kind: kind as Exclude<TrustState['kind'], 'none'>, entry };
}

/** The message as the adapter would have handed it over, with the unread parts genuinely absent. */
function withoutParts(email: EmailMessage, missing: readonly MessagePart[]): EmailMessage {
  const copy = { ...email };
  for (const part of missing) {
    if (part === 'sender') {
      delete copy.senderEmail;
      delete copy.senderName;
    }
    if (part === 'subject') delete copy.subject;
    if (part === 'body') copy.bodyText = '';
  }
  return copy;
}

/** A stand-in report, in the shape `buildDiagnostic` produces from a real page. */
function cannedDiagnostic(missing: readonly MessagePart[]): string {
  return formatDiagnostic({
    adapter: 'gmail-dom',
    version: 'harness',
    browser: 'Chrome/0.0.0.0',
    missing,
    probes: [
      { group: 'messageContainer', scope: 'message', candidate: 0 },
      { group: 'senderSpan', scope: 'none', candidate: -1 },
      { group: 'senderTextual', scope: 'none', candidate: -1 },
      { group: 'subject', scope: 'document', candidate: 1 },
      { group: 'body', scope: 'message', candidate: 0 },
    ],
  });
}

const fixtures: Fixture[] = (JSON.parse(__PHISHLENS_FIXTURES__) as RawFixture[]).map(toFixture);

/**
 * A canned verdict, so the AI section renders without a model present.
 *
 * Shaped like something the on-device model actually returns: a risk it can justify in words, with
 * `reasons` that stay clear of domains and links — the boundary `llm/prompt.ts` draws, since those are
 * claims the model cannot verify and deterministic code already checks.
 */
function cannedVerdict(email: EmailMessage, aiMode: AiMode): SemanticAnalysis {
  const urgent = /verif|suspend|immediat|within 24|expir|urgent/iu.test(
    `${email.subject ?? ''} ${email.bodyText}`,
  );
  // `off` produces no verdict at all, so its source value is never rendered.
  const source = aiMode === 'off' ? 'local' : aiMode;
  const model = aiMode === 'server' ? 'qwen2.5:7b' : 'harness-canned';

  return urgent
    ? {
        risk: 78,
        categories: ['credential_phishing', 'social_engineering'],
        reasons: [
          'Creates time pressure by threatening loss of access',
          'Asks the reader to confirm account details to avoid a consequence',
          'Uses an impersonal greeting for an account-specific claim',
        ],
        confidence: 0.82,
        source,
        model,
      }
    : {
        risk: 12,
        categories: ['benign'],
        reasons: ['Reads as routine correspondence with no request for credentials or payment'],
        confidence: 0.74,
        source,
        model,
      };
}

function cannedAnalyzer(email: EmailMessage, aiMode: AiMode): SemanticAnalyzer {
  return {
    id: 'harness',
    isAvailable: () => Promise.resolve(true),
    analyze: () => Promise.resolve(cannedVerdict(email, aiMode)),
  };
}

/**
 * `ready` runs the genuine semantic path, so the llm signal, its score and its wording all come from
 * `semanticToSignals` rather than being drawn by hand. The other states produce no signal by
 * definition, so stamping the status onto a deterministic result is exactly what the engine would
 * return.
 */
async function resultFor(
  email: EmailMessage,
  semantic: SemanticStatus,
  aiMode: AiMode,
): Promise<AnalysisResult> {
  if (semantic === 'ready') return analyze(email, cannedAnalyzer(email, aiMode));
  const { context: _context, ...deterministic } = analyzeDeterministic(email);
  return withSemanticStatus(deterministic, semantic);
}

// ---------------------------------------------------------------------------
// The mock message
// ---------------------------------------------------------------------------

function headerRow(email: EmailMessage): { row: HTMLElement; right: HTMLElement } {
  const name = email.senderName ?? email.senderEmail ?? 'Unknown sender';
  const right = el('div', {
    class: 'header-right',
    children: [el('span', { text: '10:24' })],
  });

  const row = el('div', {
    class: 'header',
    children: [
      el('div', { class: 'avatar', text: name.slice(0, 1) }),
      el('div', {
        class: 'who',
        children: [
          el('div', {
            children: [
              el('span', { class: 'sender-name', text: name }),
              el('span', {
                class: 'sender-address',
                text: email.senderEmail === undefined ? '' : ` <${email.senderEmail}>`,
              }),
            ],
          }),
          el('div', { class: 'recipient', text: 'to me' }),
        ],
      }),
      right,
    ],
  });

  return { row, right };
}

function bodyBlock(email: EmailMessage): HTMLElement {
  const children: Node[] = [el('div', { text: email.bodyText })];

  for (const link of email.links) {
    children.push(
      el('div', {
        children: [
          el('a', {
            text: link.text,
            attrs: { href: link.href },
            // Nothing in a fixture is ever dereferenced, here or in the extension.
            on: {
              click: (event) => {
                event.preventDefault();
              },
            },
          }),
        ],
      }),
    );
  }

  if (email.attachments.length > 0) {
    children.push(
      el('div', {
        class: 'attachments',
        children: email.attachments.map((a) =>
          el('span', { class: 'attachment', text: a.filename }),
        ),
      }),
    );
  }

  return el('div', { class: 'body', children });
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const panel = new Panel({
  onFocusSignal: () => undefined,
  onBlurSignal: () => undefined,
  onClose: () => {
    panel.close();
    setParam('card', '0');
  },
  // There is no storage here, so the button moves the URL instead — which is also the only way to see
  // what the card looks like after the click.
  onTrustChange: (_entry, trusted) => {
    setParam('trust', trusted ? 'trusted' : 'offer');
  },
});

const stage = document.querySelector<HTMLElement>('#stage');
const listMarks = new ListMarks();

async function renderFull(state: HarnessState): Promise<void> {
  if (stage === null) return;
  const { fixture, cardOpen } = state;
  const { row, right } = headerRow(fixture.email);

  stage.replaceChildren(
    el('div', {
      class: 'reader',
      children: [
        el('h1', { class: 'subject', text: fixture.email.subject ?? '(no subject)' }),
        row,
        bodyBlock(fixture.email),
      ],
    }),
  );

  const view = await viewFor(state);
  const badge = new Badge({
    onActivate: () => {
      panel.toggle(view);
    },
  });
  badge.attach(right);
  if (view.kind === 'unreadable') badge.setUnreadable();
  else badge.setResult(view.result);

  if (cardOpen) panel.open(view);
  else panel.close();
}

/**
 * The card's whole input, chosen the way the controller chooses it: an unscorable extraction never
 * reaches the engine, so the harness must not build a result for one either.
 */
async function viewFor(state: HarnessState): Promise<PanelView> {
  const { fixture, semantic, aiMode, missing } = state;

  if (!isScorable(missing)) {
    return {
      kind: 'unreadable',
      // Actually removed, not merely declared missing: the card names the message it is about, and a
      // sender it could not read has to be absent for that line to read as a reader would see it.
      email: withoutParts(fixture.email, missing),
      missing,
      diagnostic: cannedDiagnostic(missing),
    };
  }
  return {
    kind: 'result',
    result: await resultFor(fixture.email, semantic, aiMode),
    aiMode,
    email: fixture.email,
    semantic,
    trust: trustFor(state.trust, fixture.email),
  };
}

/**
 * One header row per classification, to show the badge's range in a single image.
 *
 * The examples are chosen by analysing the corpus rather than by being listed here, so the image can
 * only ever show bands the fixtures genuinely produce — currently three, since nothing in the corpus is
 * designed to land in `caution`. A hardcoded list would quietly start lying the day a fixture's score
 * moved across a threshold.
 */
async function renderBadges(semantic: SemanticStatus): Promise<void> {
  if (stage === null) return;
  panel.close();
  const rows = el('div', { class: 'rows' });
  stage.replaceChildren(rows);

  const scored = await Promise.all(
    // The badge shows a score, which no mode changes, so this view is deliberately mode-agnostic.
    fixtures.map(async (fixture) => ({
      fixture,
      result: await resultFor(fixture.email, semantic, 'local'),
    })),
  );

  for (const band of BANDS) {
    const example = scored.find((s) => s.result.classification === band);
    if (example === undefined) continue;
    const { row, right } = headerRow(example.fixture.email);
    rows.append(row);
    const badge = new Badge({ onActivate: () => undefined });
    badge.attach(right);
    badge.setResult(example.result);
  }

  // Last, and not one of the bands: "not checked" is the absence of a reading rather than a step on the
  // same scale. The README documents it in the same table, so the image has to show it.
  const first = scored[0];
  if (first !== undefined) {
    const { row, right } = headerRow(withoutParts(first.fixture.email, ['sender']));
    rows.append(row);
    const badge = new Badge({ onActivate: () => undefined });
    badge.attach(right);
    badge.setUnreadable();
  }
}

/**
 * A message list, in Gmail's own row shape, with the real `ListMarks` scanner over it.
 *
 * The whole corpus as one inbox, which is the view that answers the question the feature lives or dies on:
 * how much of an ordinary inbox ends up marked. Reading that off a screenshot is the only way to judge it
 * — a test can assert that no legitimate fixture is marked, but not whether the result looks like a tool
 * worth leaving switched on.
 *
 * The markup mirrors `SELECTORS.listRow` and its neighbours rather than being styled to taste: the point
 * is to exercise the same selectors that run against Gmail, so a candidate list that has gone stale shows
 * up here as a missing mark.
 */
function renderList(): void {
  if (stage === null) return;
  panel.close();
  listMarks.stop();

  const rows = fixtures.map((fixture) => {
    const email = fixture.email;
    return el('tr', {
      class: 'zA',
      children: [
        el('td', {
          class: 'xY',
          children: [
            el('div', {
              class: 'yW',
              children: [
                el('span', {
                  text: email.senderName === '' ? (email.senderEmail ?? '') : (email.senderName ?? ''),
                  attrs: {
                    email: email.senderEmail ?? '',
                    name: email.senderName ?? '',
                  },
                }),
              ],
            }),
          ],
        }),
        el('td', {
          class: 'xY a4W',
          children: [
            el('div', {
              class: 'y6',
              children: [
                el('span', { class: 'bog', text: email.subject ?? '(no subject)' }),
                el('span', { class: 'snippet', text: ` — ${email.bodyText.slice(0, 90)}` }),
              ],
            }),
          ],
        }),
      ],
    });
  });

  const list = el('table', { class: 'list', children: [el('tbody', { children: rows })] });
  stage.replaceChildren(list);
  listMarks.start(list, () => 'sam.okafor@northwind-logistics.com');
}

async function renderCardOnly(state: HarnessState): Promise<void> {
  if (stage === null) return;
  const frame = el('div', { class: 'card-frame' });
  stage.replaceChildren(frame);

  panel.open(await viewFor(state));

  // The card is built as a child of <body>, as it is in Gmail. Moving the host into the frame leaves
  // the component itself untouched.
  const host = document.querySelector('#phishlens-panel-host');
  if (host === null) return;
  frame.append(host);
  flattenForStillImage(host);
}

/**
 * Removes the two behaviours that are right in Gmail and wrong in a photograph, by adding a stylesheet
 * to the card's shadow root. The component's own CSS is not modified — this applies only in `view=card`.
 *
 *  - `position: fixed` pins the card to a viewport corner, so where it lands in the picture depends on
 *    the window size, and Chrome clamps small windows while still capturing at the size asked for.
 *    Normal flow puts it at a known offset instead.
 *  - The entrance animation fades and rises over 140ms, so a capture can land mid-transition and come
 *    out faint or displaced.
 *
 * The height cap is *kept*, at the value a normal window produces, so the card is the size and shape a
 * reader sees, scrolled content included.
 */
function flattenForStillImage(host: Element): void {
  const style = document.createElement('style');
  style.textContent = `
    .panel {
      /* relative, not static: the state-colour strip is an absolutely positioned ::before, and a static
         panel is not its containing block, so the strip escapes to the page edge. */
      position: relative;
      max-height: 620px;
      animation: none;
    }
  `;
  host.shadowRoot?.append(style);
}

/** Everything the URL selects, as one value. */
interface HarnessState {
  fixture: Fixture;
  semantic: SemanticStatus;
  aiMode: AiMode;
  missing: readonly MessagePart[];
  trust: string;
  cardOpen: boolean;
}

async function render(): Promise<void> {
  const params = new URLSearchParams(window.location.search);
  document.body.dataset['bare'] = params.get('bare') ?? '0';
  reportViewport();

  const semantic = pick(params.get('semantic'), SEMANTIC_STATES, 'ready');
  const aiMode = pick(params.get('ai'), AI_MODES, 'local');
  const view = pick(params.get('view'), VIEWS, 'full');
  document.body.dataset['view'] = view;
  const missingParam = pick(params.get('missing'), MISSING_STATES, 'none');
  const trust = pick(params.get('trust'), TRUST_STATES, 'none');
  const fixture = fixtures.find((f) => f.name === params.get('fixture')) ?? fixtures[0];
  if (fixture === undefined) return;

  const state: HarnessState = {
    fixture,
    semantic,
    aiMode,
    missing: missingParam === 'none' ? [] : [missingParam as MessagePart],
    trust,
    cardOpen: params.get('card') === '1',
  };

  syncControls(state, view, missingParam);

  // Every view other than `list` shows one message, so the scanner has nothing to mark and its observer
  // would otherwise stay attached to a stage it no longer owns.
  if (view !== 'list') listMarks.stop();

  if (view === 'badges') await renderBadges(semantic);
  // `card` shows the card alone on an empty page. It stays pinned bottom-right as it is in Gmail, so
  // sizing the window to the card crops to it exactly without any screenshot post-processing.
  else if (view === 'card') await renderCardOnly(state);
  else if (view === 'list') renderList();
  else await renderFull(state);
}

function pick<T extends string>(value: string | null, allowed: readonly T[], fallback: T): T {
  return allowed.find((a) => a === value) ?? fallback;
}

/**
 * Publishes the layout viewport in the title, where `chrome --headless --dump-dom` can read it.
 *
 * `scripts/screenshots.mjs` crops by sizing the window, which only works if the size Chrome lays out at
 * is the size it captures. Those disagree under some flag combinations, and the failure looks like a
 * mysteriously clipped image, so the script asserts the geometry instead of assuming it.
 */
function reportViewport(): void {
  document.title = `PhishLens harness ${String(window.innerWidth)}x${String(window.innerHeight)}@${String(window.devicePixelRatio)}`;
}

// ---------------------------------------------------------------------------
// Controls, which only ever write to the URL so that every state stays linkable
// ---------------------------------------------------------------------------

function setParam(key: string, value: string): void {
  const url = new URL(window.location.href);
  url.searchParams.set(key, value);
  window.history.replaceState(null, '', url);
  void render();
}

function syncControls(state: HarnessState, view: View, missing: string): void {
  fillSelect('#fixture', fixtures.map((f) => f.name), state.fixture.name);
  fillSelect('#semantic', [...SEMANTIC_STATES], state.semantic);
  fillSelect('#ai', [...AI_MODES], state.aiMode);
  fillSelect('#view', [...VIEWS], view);
  fillSelect('#missing', [...MISSING_STATES], missing);
  fillSelect('#trust', [...TRUST_STATES], state.trust);

  const card = document.querySelector<HTMLInputElement>('#card');
  if (card !== null) card.checked = state.cardOpen;

  const hint = document.querySelector<HTMLElement>('#hint');
  const description = state.fixture.description;
  if (hint !== null) hint.textContent = description;
}

function fillSelect(selector: string, options: string[], selected: string): void {
  const node = document.querySelector<HTMLSelectElement>(selector);
  if (node === null) return;
  if (node.options.length !== options.length) {
    node.replaceChildren(
      ...options.map((value) => el('option', { text: value, attrs: { value } })),
    );
  }
  node.value = selected;
}

for (const [selector, key] of [
  ['#fixture', 'fixture'],
  ['#semantic', 'semantic'],
  ['#ai', 'ai'],
  ['#view', 'view'],
  ['#missing', 'missing'],
  ['#trust', 'trust'],
] as const) {
  document.querySelector<HTMLSelectElement>(selector)?.addEventListener('change', (event) => {
    const target = event.currentTarget;
    if (target instanceof HTMLSelectElement) setParam(key, target.value);
  });
}

document.querySelector<HTMLInputElement>('#card')?.addEventListener('change', (event) => {
  const target = event.currentTarget;
  if (target instanceof HTMLInputElement) setParam('card', target.checked ? '1' : '0');
});

window.addEventListener('popstate', () => {
  void render();
});

void render();
