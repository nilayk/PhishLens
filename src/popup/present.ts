/**
 * What the popup says, separated from how it is drawn.
 *
 * Pure: no DOM, no `chrome`, no storage. That is what lets the wording be asserted in Vitest, which
 * matters more here than anywhere else in the UI — the popup is the surface a user consults when
 * something looks wrong, so a sentence that misdescribes the state is worse than no popup at all.
 *
 * The rule the whole file follows: never let "nothing was found" and "nothing was checked" share a
 * phrasing. Everything else is detail.
 */
import type { AiMode, MessagePart, SemanticStatus, Settings } from '../shared/types.js';
import type { TabStatus } from '../shared/messaging.js';
import {
  CLASSIFICATION_GLYPHS,
  CLASSIFICATION_LABELS,
  UNREADABLE_GLYPH,
  UNREADABLE_LABEL,
} from '../ui/labels.js';
import { isModelServerConfigured } from '../shared/settings.js';

/**
 * `not-gmail` and `unreachable` are the popup's own states, not the tab's: no content script answered,
 * for the two reasons that mean different things to a user. Every other state comes from the tab.
 */
export type PopupState = TabStatus | { kind: 'not-gmail' } | { kind: 'unreachable' };

/** Drives the chip's colour. `idle` is "nothing to report", `unknown` is "could not tell". */
export type Tone = 'low' | 'caution' | 'suspicious' | 'high-risk' | 'unknown' | 'idle';

export interface Headline {
  /** Empty when the state has no glyph, rather than a placeholder that looks like a verdict. */
  glyph: string;
  label: string;
  /** `"58/100"`, or empty when nothing was scored. */
  score: string;
  tone: Tone;
  /** One sentence under the chip. Always present: a bare chip invites the wrong reading. */
  note: string;
}

const PART_NAMES: Readonly<Record<MessagePart, string>> = {
  sender: 'who it is from',
  subject: 'its subject',
  body: 'its text',
};

/** "who it is from", "who it is from and its text" — a list a sentence can contain. */
function describeParts(missing: readonly MessagePart[]): string {
  const names = missing.map((part) => PART_NAMES[part]);
  if (names.length === 0) return 'this message';
  if (names.length === 1) return names[0] ?? 'this message';
  return `${names.slice(0, -1).join(', ')} and ${String(names[names.length - 1])}`;
}

export function headline(state: PopupState): Headline {
  switch (state.kind) {
    case 'not-gmail':
      return {
        glyph: '',
        label: 'Nothing to check here',
        score: '',
        tone: 'idle',
        note: 'PhishLens only runs on Gmail. Open a message there and its assessment appears here.',
      };
    case 'unreachable':
      // Gmail is open and nothing answered, which happens when the extension is reloaded or updated
      // underneath a tab that was already open. The tab looks normal and silently checks nothing, so
      // this is the one state whose whole value is naming the fix.
      return {
        glyph: UNREADABLE_GLYPH,
        label: 'Not running in this tab',
        score: '',
        tone: 'unknown',
        note: 'This tab was open before PhishLens started or was updated. Reload it and messages will be checked again.',
      };
    case 'no-message':
      return {
        glyph: '',
        label: 'No message open',
        score: '',
        tone: 'idle',
        note: 'Open a message and PhishLens checks it as it loads.',
      };
    case 'pending':
      return {
        glyph: '',
        label: 'Checking…',
        score: '',
        tone: 'idle',
        note: 'Technical checks take a few milliseconds.',
      };
    case 'unreadable':
      return {
        glyph: UNREADABLE_GLYPH,
        label: UNREADABLE_LABEL,
        score: '',
        tone: 'unknown',
        // Says outright that this is not an all-clear. The badge and card carry the same sentence, and
        // this is the surface most likely to be read on its own.
        note: `PhishLens could not read ${describeParts(state.missing)}, so it has not scored it. That is not a judgement that the message is safe.`,
      };
    case 'scored':
      return {
        glyph: CLASSIFICATION_GLYPHS[state.classification],
        label: CLASSIFICATION_LABELS[state.classification],
        score: `${String(state.score)}/100`,
        tone: state.classification,
        note:
          state.findings === 0
            ? 'None of the technical checks found anything.'
            : 'Every point of this score comes from a finding you can read.',
      };
  }
}

/** The findings count, or `null` when the state has no findings to count. */
export function findingsLine(state: PopupState): string | null {
  if (state.kind !== 'scored') return null;
  if (state.findings === 0) return 'No findings';
  return state.findings === 1 ? '1 finding' : `${String(state.findings)} findings`;
}

/**
 * The label for the button that opens the card, or `null` when there is no card to open.
 *
 * Worded per state rather than fixed: "Show the full assessment" on a message that was never assessed
 * would promise the one thing the card exists to say does not exist.
 */
export function cardButtonLabel(state: PopupState): string | null {
  if (state.kind === 'scored') return 'Show the full assessment';
  if (state.kind === 'unreadable') return 'Show what could not be read';
  return null;
}

// ---------------------------------------------------------------------------
// The AI row
// ---------------------------------------------------------------------------

/**
 * Name of whatever is doing the reading, as a row label. Matches `ANALYZER_NAMES` in `ui/format.ts` in
 * substance but not in shape: that file needs sentence-initial forms, this one needs headings.
 */
const MODE_LABELS: Readonly<Record<AiMode, string>> = {
  off: 'AI analysis',
  local: 'On-device model',
  cloud: 'Analysis service',
  server: 'Your model server',
};

/**
 * A `Record` so a new `SemanticStatus` cannot compile until the popup has wording for it, and short
 * enough to sit on one line. `pending` is a live state here, not a note about a finished result.
 */
const STATUS_TEXT: Readonly<Record<SemanticStatus, string>> = {
  ready: 'Assessment ready',
  pending: 'Reading the message…',
  off: 'Switched off — technical checks only',
  unavailable: 'Unavailable',
  'no-output': 'Returned nothing usable for this message',
  error: 'Could not finish',
  cancelled: 'Interrupted',
};

export interface AiRow {
  label: string;
  detail: string;
  /**
   * True when a connection test would tell the user something. Only ever set for a configured model
   * server: the on-device model has nothing to test — it is either in the browser or it is not — and
   * offering a button that cannot help is how a diagnostic surface loses its credibility.
   */
  testable: boolean;
  /** Set when the state has a cause the user can act on. Rendered next to the detail. */
  fix: string | null;
}

export function aiRow(settings: Settings, state: PopupState): AiRow {
  const label = MODE_LABELS[settings.aiMode];
  const testable = isModelServerConfigured(settings);

  if (settings.aiMode === 'off') {
    return { label, detail: STATUS_TEXT.off, testable: false, fix: null };
  }

  if (settings.aiMode === 'server' && !testable) {
    return {
      label,
      detail: 'Not finished setting up',
      testable: false,
      fix: 'Set the server address and model in settings.',
    };
  }

  // A message nothing could be read from never reached the semantic stage, and saying the model is
  // "ready when you open a message" while one is open reads as a second, contradictory failure.
  if (state.kind === 'unreadable') {
    return { label, detail: 'Not used — this message was not read', testable, fix: null };
  }

  // Only a scored message has been through the semantic stage. Before that there is a configuration to
  // report and nothing else, and inventing a status for it would mean showing "unavailable" for a model
  // that is merely unasked.
  if (state.kind !== 'scored') {
    return { label, detail: 'Ready when you open a message', testable, fix: null };
  }

  return {
    label,
    detail: STATUS_TEXT[state.semantic],
    testable,
    fix: fixFor(state.semantic, settings.aiMode),
  };
}

/**
 * The one line of advice, where there is any worth giving.
 *
 * `no-output` and `error` on a user-run server are the two that sent people to a console in practice —
 * a rejected origin and a reply truncated by a reasoning model both surface as silence — so those are
 * the ones that name the button that explains them.
 */
function fixFor(status: SemanticStatus, aiMode: AiMode): string | null {
  if (status === 'unavailable') {
    return aiMode === 'local'
      ? 'This browser has no built-in model. Technical checks are unaffected; a model you run yourself works as an alternative.'
      : 'PhishLens could not reach it. Test the connection to see why.';
  }
  if (aiMode === 'server' && (status === 'no-output' || status === 'error')) {
    return 'Test the connection to see what the server reports.';
  }
  return null;
}
