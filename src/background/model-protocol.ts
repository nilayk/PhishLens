/**
 * What to ask an OpenAI-compatible model server for, and how to read what comes back.
 *
 * Separate from `index.ts` because it is the part of the model-server path with no `chrome` and no socket
 * in it, and therefore the part that can be tested. That matters more here than the file count: every
 * decision below exists because a real runner behaved in a way the code did not expect, and the next
 * runner update is as likely to move the ground again. A protocol detail nothing asserts is one that
 * regresses silently — and its symptom, as this feature has already demonstrated, is a card politely
 * saying the model returned nothing usable.
 */
import { RESPONSE_SCHEMA } from '../analysis/llm/prompt.js';

/**
 * Request shapes to try, strictest first, each rung asking for less than the one above.
 *
 * Two optional fields are involved and support for both varies by runner and version, which is why this is
 * one ladder rather than two independent choices: a server that does not recognise a field *rejects the
 * request* rather than ignoring the field, so asking is the only way to learn what it accepts.
 *
 *  - `response_format` makes the answer machine-readable at the server instead of by our parsing.
 *  - `reasoning_effort: 'none'` asks a reasoning model not to think aloud first. Worth requesting even
 *    though the token budget now tolerates thinking, because thinking is most of the latency of a local
 *    model and this is a structured judgement rather than a puzzle that benefits from working out.
 *
 * A rung that fails costs one round trip and no generation, so old servers pay for this and current ones
 * do not. The parser tolerates fenced and prose-wrapped JSON regardless, which is what makes the last
 * rung — asking for no structure at all — still viable.
 */
export const REQUEST_VARIANTS: readonly Readonly<Record<string, unknown>>[] = Object.freeze([
  Object.freeze({
    response_format: {
      type: 'json_schema',
      json_schema: { name: 'assessment', strict: true, schema: RESPONSE_SCHEMA },
    },
    reasoning_effort: 'none',
  }),
  Object.freeze({ response_format: { type: 'json_object' }, reasoning_effort: 'none' }),
  Object.freeze({ response_format: { type: 'json_object' } }),
  Object.freeze({}),
]);

/**
 * Ceiling on generated tokens. Stops a runaway model streaming indefinitely, and nothing else.
 *
 * The assessment is around 150 tokens and 500 looked generous until a reasoning model met it: a
 * Qwen3-class model spends several hundred tokens thinking *before* answering, the runner counts those
 * against this budget, and the reply arrives cut off mid-string — `finish_reason: 'length'`, unparseable,
 * reported to the user as a model that returned nothing usable. Nothing in that message points at a token
 * limit, which is what made it expensive to find. So the budget assumes a model thinks at length even
 * though the request asks it not to, because `reasoning_effort` is not honoured everywhere. Unused tokens
 * cost nothing; a truncated answer costs the whole feature.
 */
export const MAX_TOKENS = 2000;

/**
 * An HTTP failure worded so the reader can act on it.
 *
 * 403 earns its own sentence because it is the first thing nearly everyone pointing this at Ollama sees,
 * and because the cause is invisible from here: Chrome attaches `Origin: chrome-extension://<id>` to every
 * request the worker makes, and Ollama refuses any origin it was not told to expect. Nothing in the
 * extension can work around it — the header cannot be suppressed, and the address, the port and the
 * permission grant are all correct — so the only useful thing to report is which setting the server needs.
 * "Returned 403" sends the reader hunting for a fault that is not there.
 */
export function describeHttpFailure(status: number): string {
  if (status === 401 || status === 403) {
    return `model server refused the request (${String(status)}): it is not configured to accept requests from browser extensions. Ollama needs OLLAMA_ORIGINS to include chrome-extension://* before it starts; LM Studio and others have an equivalent CORS setting.`;
  }
  if (status === 404) {
    return 'model server returned 404: there is no OpenAI-compatible API at that address. Ollama serves one under /v1.';
  }
  return `model server returned ${String(status)}`;
}

/** True for the one class of failure worth asking a different way: a rejection of the request's shape. */
export function isShapeRejection(status: number): boolean {
  return status === 400 || status === 422;
}

/**
 * The assistant's text from a chat-completions envelope, without trusting its shape.
 *
 * Reasoning fields are deliberately not read. When a runner separates thinking from the answer, the
 * thinking often contains an earlier draft of the same JSON with different numbers in it, and picking that
 * up would show the reader a verdict the model discarded.
 */
export function completionText(body: unknown): string | null {
  if (body === null || typeof body !== 'object') return null;
  const choices = (body as { choices?: unknown }).choices;
  if (!Array.isArray(choices) || choices.length === 0) return null;
  const message = (choices[0] as { message?: unknown }).message;
  if (message === null || typeof message !== 'object') return null;
  const content = (message as { content?: unknown }).content;
  return typeof content === 'string' && content.trim() !== '' ? content : null;
}

export interface UnusableAnswer {
  /** The server's own account of why generation stopped. `length` means the budget ran out. */
  finish: string;
  contentChars: number;
  /** Characters the model spent thinking, when the runner reports them separately. */
  thoughtChars: number;
  truncated: boolean;
}

/**
 * What was wrong with an answer that could not be used, as fields rather than prose.
 *
 * Recorded because this was the one silent failure in the path and the most confusing to be on the
 * receiving end of: HTTP 200, a model plainly running, and nothing to show. The shape separates a
 * truncated reply from a refusal from prose the parser gave up on, which is the difference between raising
 * a limit, fixing a configuration, and changing a prompt.
 */
export function describeUnusable(body: unknown, content: string | null): UnusableAnswer {
  const choice = (body as { choices?: unknown[] } | null)?.choices?.[0];
  const message = (choice as { message?: Record<string, unknown> } | undefined)?.message;
  const reasoning = message?.['reasoning'] ?? message?.['reasoning_content'];
  const finish = (choice as { finish_reason?: unknown } | undefined)?.finish_reason;

  return {
    finish: typeof finish === 'string' ? finish : 'unknown',
    contentChars: content?.length ?? 0,
    thoughtChars: typeof reasoning === 'string' ? reasoning.length : 0,
    truncated: finish === 'length',
  };
}
