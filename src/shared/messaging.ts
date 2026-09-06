/**
 * The content-script ↔ service-worker protocol.
 *
 * Kept deliberately tiny. The worker is stateless (docs/ARCHITECTURE.md §2), so every message is a
 * complete, self-contained request; nothing here depends on a previous message having been handled
 * by the same worker instance.
 */
import type { SemanticAnalysis, Settings } from './types.js';

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
