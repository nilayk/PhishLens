/**
 * Strict validation of model output.
 *
 * The contract is all-or-nothing: either the output matches the schema and we get a
 * `SemanticAnalysis`, or we get `null` and the `llm` category contributes zero. There is no partial
 * trust and no field-level salvaging, because a model that returned a malformed object is a model
 * whose *values* we have no reason to trust either — and because a hostile email may well be the
 * reason the output is malformed.
 */
import { collapseWhitespace, truncate } from '../../shared/text.js';
import {
  SEMANTIC_CATEGORIES,
  type SemanticAnalysis,
  type SemanticCategory,
} from '../../shared/types.js';
import { SEMANTIC_SCORING } from '../scoring/config.js';

const CATEGORY_SET: ReadonlySet<string> = new Set(SEMANTIC_CATEGORIES);
const MAX_REASON_CHARS = 240;

/**
 * Extracts a JSON object from a model response.
 *
 * Models wrap JSON in code fences and add lead-in prose even when told not to. Tolerating that is
 * about the *envelope* only; the object inside is still validated strictly.
 */
export function extractJsonObject(raw: string): unknown {
  const text = raw.trim();
  if (text === '') return null;

  const fenced = /```(?:json)?\s*([\s\S]*?)```/iu.exec(text);
  const candidates = [fenced?.[1]?.trim(), text, sliceOutermostBraces(text)].filter(
    (c): c is string => c !== undefined && c !== '',
  );

  for (const candidate of candidates) {
    try {
      const parsed: unknown = JSON.parse(candidate);
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch {
      // Try the next candidate.
    }
  }
  return null;
}

function sliceOutermostBraces(text: string): string {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  return start >= 0 && end > start ? text.slice(start, end + 1) : '';
}

/**
 * Validates and normalises a parsed object into a `SemanticAnalysis`.
 * Returns `null` if anything required is missing or the wrong type.
 */
export function parseSemanticAnalysis(
  raw: unknown,
  source: SemanticAnalysis['source'],
  model?: string,
): SemanticAnalysis | null {
  const object = typeof raw === 'string' ? extractJsonObject(raw) : raw;
  if (object === null || typeof object !== 'object' || Array.isArray(object)) return null;

  const record = object as Record<string, unknown>;

  const risk = toBoundedNumber(record['risk'], 0, 100);
  if (risk === null) return null;

  const confidence = toBoundedNumber(record['confidence'], 0, 1);
  if (confidence === null) return null;

  const reasons = toReasons(record['reasons']);
  if (reasons.length === 0) return null;

  const categories = toCategories(record['categories']);

  return {
    risk: Math.round(risk),
    categories,
    reasons,
    confidence,
    source,
    ...(model !== undefined && model !== '' ? { model } : {}),
  };
}

function toBoundedNumber(value: unknown, min: number, max: number): number | null {
  const numeric =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && value.trim() !== ''
        ? Number(value)
        : Number.NaN;
  if (!Number.isFinite(numeric)) return null;
  return Math.min(Math.max(numeric, min), max);
}

function toReasons(value: unknown): string[] {
  const list = Array.isArray(value) ? value : typeof value === 'string' ? [value] : [];
  return list
    .filter((r): r is string => typeof r === 'string')
    .map((r) => truncate(collapseWhitespace(r), MAX_REASON_CHARS))
    .filter((r) => r.length > 0)
    .slice(0, SEMANTIC_SCORING.maxReasons);
}

function toCategories(value: unknown): SemanticCategory[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<SemanticCategory>();
  for (const entry of value) {
    if (typeof entry !== 'string') continue;
    const normalized = entry.trim().toLowerCase().replace(/[\s-]+/gu, '_');
    if (CATEGORY_SET.has(normalized)) seen.add(normalized as SemanticCategory);
    if (seen.size >= 4) break;
  }
  return [...seen];
}
