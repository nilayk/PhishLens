/**
 * The content-script ↔ service-worker protocol.
 *
 * Kept deliberately tiny. The worker is stateless (docs/ARCHITECTURE.md §2), so every message is a
 * complete, self-contained request; nothing here depends on a previous message having been handled
 * by the same worker instance.
 */
import type {
  Classification,
  MessagePart,
  SemanticAnalysis,
  SemanticStatus,
  Settings,
} from './types.js';

export interface GetSettingsRequest {
  type: 'GET_SETTINGS';
}

export interface SetSettingsRequest {
  type: 'SET_SETTINGS';
  patch: Partial<Settings>;
}

/**
 * Payload for the (unbuilt) cloud path. Note what is *absent*: no raw body, no recipient address, no
 * attachment bytes, no message id. Built by `src/analysis/llm/redact.ts`.
 */
export interface CloudAnalyzeRequest {
  type: 'CLOUD_ANALYZE';
  payload: {
    subject: string;
    /** Truncated body with email addresses reduced to their domains. */
    bodyExcerpt: string;
    senderDomain: string;
    senderNameShape: string;
    replyToDomain?: string;
    linkDomains: string[];
    attachmentExtensions: string[];
    /** Ids of deterministic signals already found, so the backend need not re-derive them. */
    deterministicSignalIds: string[];
  };
}

/**
 * Prompt for a model server the user runs. The two strings are exactly what the on-device model is
 * given, because that is the mode this one substitutes for.
 *
 * Note what is *not* here: no URL and no model name. The worker reads both from settings, so the only
 * address it can ever be made to call is one that survived `normalizeModelBaseUrl`. Accepting an
 * endpoint over this channel would make the worker a general-purpose fetcher for whatever could send
 * it a message.
 */
export interface ModelServerAnalyzeRequest {
  type: 'MODEL_SERVER_ANALYZE';
  payload: {
    system: string;
    user: string;
  };
}

/** Lists what the configured server has loaded, so the options page can offer real model names. */
export interface ListModelsRequest {
  type: 'LIST_MODELS';
}

export type ExtensionRequest =
  | GetSettingsRequest
  | SetSettingsRequest
  | CloudAnalyzeRequest
  | ModelServerAnalyzeRequest
  | ListModelsRequest;

export type ExtensionResponse =
  | { ok: true; type: 'SETTINGS'; settings: Settings }
  | { ok: true; type: 'SEMANTIC'; analysis: SemanticAnalysis | null }
  | { ok: true; type: 'MODELS'; models: string[] }
  | { ok: false; error: string };

const REQUEST_TYPES: ReadonlySet<string> = new Set([
  'GET_SETTINGS',
  'SET_SETTINGS',
  'CLOUD_ANALYZE',
  'MODEL_SERVER_ANALYZE',
  'LIST_MODELS',
]);

export function isExtensionRequest(value: unknown): value is ExtensionRequest {
  if (value === null || typeof value !== 'object') return false;
  const type = (value as Record<string, unknown>)['type'];
  return typeof type === 'string' && REQUEST_TYPES.has(type);
}

// ---------------------------------------------------------------------------
// The popup ↔ content-script channel
// ---------------------------------------------------------------------------

/**
 * What the toolbar popup can ask the tab about the message on screen.
 *
 * A separate union from `ExtensionRequest` because it travels a different route — `chrome.tabs.
 * sendMessage`, which reaches only content scripts — and is answered by different code. Merging them
 * would put requests the worker cannot handle into the worker's exhaustive switch, and requests the
 * content script cannot handle into its own.
 *
 * Deliberately read-only apart from `OPEN_PANEL`, which asks the tab to show the card it would have
 * shown had the badge been clicked. Nothing here can start an analysis or change a score: a popup that
 * could would be a second, differently-behaved entry point into the same state.
 */
export interface GetTabStatusRequest {
  type: 'GET_TAB_STATUS';
}

export interface OpenPanelRequest {
  type: 'OPEN_PANEL';
}

export type TabRequest = GetTabStatusRequest | OpenPanelRequest;

/**
 * The state of the tab, as much of it as the popup needs.
 *
 * `headlines` carries finding *titles* — the extension's own wording, not message content — so the
 * popup can say what was found without re-deriving anything. The sender and subject are deliberately
 * absent: the popup is about whether PhishLens is working, and copying mail into a second surface buys
 * nothing when the card beside the message already names it.
 */
export type TabStatus =
  | { kind: 'no-message' }
  /** Extraction succeeded and the deterministic pass has not been applied yet. Momentary. */
  | { kind: 'pending' }
  | { kind: 'unreadable'; missing: MessagePart[] }
  | {
      kind: 'scored';
      score: number;
      classification: Classification;
      findings: number;
      headlines: string[];
      semantic: SemanticStatus;
    };

export type TabResponse =
  | { ok: true; type: 'TAB_STATUS'; status: TabStatus }
  | { ok: true; type: 'ACKNOWLEDGED' }
  | { ok: false; error: string };

const TAB_REQUEST_TYPES: ReadonlySet<string> = new Set(['GET_TAB_STATUS', 'OPEN_PANEL']);

export function isTabRequest(value: unknown): value is TabRequest {
  if (value === null || typeof value !== 'object') return false;
  const type = (value as Record<string, unknown>)['type'];
  return typeof type === 'string' && TAB_REQUEST_TYPES.has(type);
}

/**
 * Asks one tab. Resolves to `null` for every reason a tab may not answer — no content script on the
 * page, a tab that has navigated away, a page still loading — because to the popup these are one case:
 * there is nothing to report about this tab.
 */
export async function sendTabMessage(
  tabId: number,
  request: TabRequest,
): Promise<TabResponse | null> {
  try {
    const response: unknown = await chrome.tabs.sendMessage(tabId, request);
    if (response === null || typeof response !== 'object') return null;
    if (typeof (response as Record<string, unknown>)['ok'] !== 'boolean') return null;
    return response as TabResponse;
  } catch {
    return null;
  }
}

/**
 * `chrome.runtime.sendMessage` rejects when no receiver is alive (a worker mid-restart, or the
 * extension being reloaded). Callers get `null` rather than an unhandled rejection.
 */
export async function sendMessage(request: ExtensionRequest): Promise<ExtensionResponse | null> {
  try {
    const response: unknown = await chrome.runtime.sendMessage(request);
    if (response === null || typeof response !== 'object') return null;
    const ok = (response as Record<string, unknown>)['ok'];
    if (typeof ok !== 'boolean') return null;
    return response as ExtensionResponse;
  } catch {
    return null;
  }
}
