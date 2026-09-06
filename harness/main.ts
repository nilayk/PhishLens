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
 *   ?fixture=microsoft-phish&semantic=ready&card=1&view=full&bare=1
 *
 * Development-only. Not bundled into the extension, and it never reaches a network or a real message.
 */
import { analyzeDeterministic, analyze, withSemanticStatus } from '../src/analysis/engine.js';
import type {
  AnalysisResult,
  Classification,
  EmailMessage,
  SemanticAnalysis,
  SemanticAnalyzer,
  SemanticStatus,
} from '../src/shared/types.js';
import { Badge } from '../src/ui/badge.js';
import { el } from '../src/ui/dom.js';
import { Panel, type PanelView } from '../src/ui/panel.js';
import { toFixture, type Fixture, type RawFixture } from '../test/fixtures/convert.js';

/** Injected by scripts/harness.mjs, so adding a fixture file needs no change here. */
declare const __PHISHLENS_FIXTURES__: string;

type View = 'full' | 'badges' | 'card';

const SEMANTIC_STATES: readonly SemanticStatus[] = [
  'ready',
  'pending',
  'unavailable',
  'no-output',
  'error',
  'cancelled',
  'off',
];

const VIEWS: readonly View[] = ['full', 'badges', 'card'];

/** Ascending, so `view=badges` reads from safest to worst. */
const BANDS: readonly Classification[] = ['low', 'caution', 'suspicious', 'high-risk'];

const fixtures: Fixture[] = (JSON.parse(__PHISHLENS_FIXTURES__) as RawFixture[]).map(toFixture);

/**
 * A canned verdict, so the AI section renders without a model present.
 *
 * Shaped like something the on-device model actually returns: a risk it can justify in words, with
 * `reasons` that stay clear of domains and links — the boundary `llm/prompt.ts` draws, since those are
 * claims the model cannot verify and deterministic code already checks.
 */
function cannedVerdict(email: EmailMessage): SemanticAnalysis {
  const urgent = /verif|suspend|immediat|within 24|expir|urgent/iu.test(
    `${email.subject ?? ''} ${email.bodyText}`,
  );

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
        source: 'local',
        model: 'harness-canned',
      }
    : {
        risk: 12,
        categories: ['benign'],
        reasons: ['Reads as routine correspondence with no request for credentials or payment'],
        confidence: 0.74,
        source: 'local',
        model: 'harness-canned',
      };
}

function cannedAnalyzer(email: EmailMessage): SemanticAnalyzer {
  return {
    id: 'harness',
    isAvailable: () => Promise.resolve(true),
    analyze: () => Promise.resolve(cannedVerdict(email)),
  };
}

/**
 * `ready` runs the genuine semantic path, so the llm signal, its score and its wording all come from
 * `semanticToSignals` rather than being drawn by hand. The other states produce no signal by
 * definition, so stamping the status onto a deterministic result is exactly what the engine would
 * return.
 */
async function resultFor(email: EmailMessage, semantic: SemanticStatus): Promise<AnalysisResult> {
  if (semantic === 'ready') return analyze(email, cannedAnalyzer(email));
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
});

const stage = document.querySelector<HTMLElement>('#stage');

async function renderFull(fixture: Fixture, semantic: SemanticStatus, cardOpen: boolean): Promise<void> {
  if (stage === null) return;
  const result = await resultFor(fixture.email, semantic);
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

  const view: PanelView = { result, aiMode: 'local', email: fixture.email, semantic };
  const badge = new Badge({
    onActivate: () => {
      panel.toggle(view);
    },
  });
  badge.attach(right);
  badge.setResult(result);

  if (cardOpen) panel.open(view);
  else panel.close();
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
    fixtures.map(async (fixture) => ({ fixture, result: await resultFor(fixture.email, semantic) })),
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
}

async function renderCardOnly(fixture: Fixture, semantic: SemanticStatus): Promise<void> {
  if (stage === null) return;
  const frame = el('div', { class: 'card-frame' });
  stage.replaceChildren(frame);

  const result = await resultFor(fixture.email, semantic);
  panel.open({ result, aiMode: 'local', email: fixture.email, semantic });

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

async function render(): Promise<void> {
  const params = new URLSearchParams(window.location.search);
  document.body.dataset['bare'] = params.get('bare') ?? '0';
  reportViewport();

  const semantic = pick(params.get('semantic'), SEMANTIC_STATES, 'ready');
  const view = pick(params.get('view'), VIEWS, 'full');
  document.body.dataset['view'] = view;
  const cardOpen = params.get('card') === '1';
  const fixture = fixtures.find((f) => f.name === params.get('fixture')) ?? fixtures[0];
  if (fixture === undefined) return;

  syncControls(fixture.name, semantic, view, cardOpen);

  if (view === 'badges') await renderBadges(semantic);
  // `card` shows the card alone on an empty page. It stays pinned bottom-right as it is in Gmail, so
  // sizing the window to the card crops to it exactly without any screenshot post-processing.
  else if (view === 'card') await renderCardOnly(fixture, semantic);
  else await renderFull(fixture, semantic, cardOpen);
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

function syncControls(
  fixtureName: string,
  semantic: SemanticStatus,
  view: View,
  cardOpen: boolean,
): void {
  fillSelect('#fixture', fixtures.map((f) => f.name), fixtureName);
  fillSelect('#semantic', [...SEMANTIC_STATES], semantic);
  fillSelect('#view', [...VIEWS], view);

  const card = document.querySelector<HTMLInputElement>('#card');
  if (card !== null) card.checked = cardOpen;

  const hint = document.querySelector<HTMLElement>('#hint');
  const description = fixtures.find((f) => f.name === fixtureName)?.description;
  if (hint !== null && description !== undefined) hint.textContent = description;
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
  ['#view', 'view'],
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
