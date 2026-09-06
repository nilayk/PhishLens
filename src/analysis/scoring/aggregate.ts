/**
 * Score aggregation — pure functions, no detector knowledge, no I/O.
 *
 * This is deliberately separable from detection so the weighting rule can be retuned or replaced
 * without touching a single detector, and so it can be unit-tested on synthetic signals that no
 * detector would ever produce.
 *
 * The rule, in order:
 *   1. clamp each signal's score to `[0, ceiling(severity)]`
 *   2. sum within a category, then cap the subtotal at that category's weight
 *   3. sum the capped subtotals and clamp to `[0, 100]`
 */
import type {
  Classification,
  SecuritySignal,
  Severity,
  SignalCategory,
} from '../../shared/types.js';
import {
  ALL_CATEGORIES,
  CLASSIFICATION_THRESHOLDS,
  DEFAULT_SCORING_CONFIG,
  SCORE_FLOORS,
  SEVERITY_CEILINGS,
  SEVERITY_ORDER,
  type CategoryWeights,
  type ScoringConfig,
  type SeverityCeilings,
} from './config.js';

export function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(Math.max(value, min), max);
}

/**
 * A single signal's effective contribution: its raw score clamped to its severity's ceiling.
 * A detector claiming 90 points at `low` severity gets 15.
 */
export function cappedSignalScore(
  signal: SecuritySignal,
  ceilings: SeverityCeilings = SEVERITY_CEILINGS,
): number {
  return clamp(signal.score, 0, ceilings[signal.severity]);
}

/**
 * One category's contribution to the total.
 *
 * Signals are summed after individual capping, then the subtotal is capped at `weight`, so a
 * category can never contribute more than its allotted share of 100 no matter how many signals fire.
 */
export function aggregateCategory(
  signals: SecuritySignal[],
  weight: number,
  ceilings: SeverityCeilings = SEVERITY_CEILINGS,
): number {
  const cap = Math.max(0, weight);
  let subtotal = 0;
  for (const signal of signals) {
    subtotal += cappedSignalScore(signal, ceilings);
    if (subtotal >= cap) return cap;
  }
  return clamp(subtotal, 0, cap);
}

export type SignalsByCategory = Partial<Record<SignalCategory, SecuritySignal[]>>;

export interface TotalScore {
  total: number;
  byCategory: Record<SignalCategory, number>;
}

/** Groups a flat signal list by category, always returning an entry for every category. */
export function groupByCategory(signals: readonly SecuritySignal[]): Record<SignalCategory, SecuritySignal[]> {
  const grouped = Object.fromEntries(
    ALL_CATEGORIES.map((c) => [c, [] as SecuritySignal[]]),
  ) as Record<SignalCategory, SecuritySignal[]>;

  for (const signal of signals) {
    // A signal whose category is not one we score is dropped rather than silently counted as
    // something else. The union type makes this unreachable in typed code, but the semantic layer
    // feeds in values that originated as model output, so it is checked at runtime.
    if (!ALL_CATEGORIES.includes(signal.category)) continue;
    grouped[signal.category].push(signal);
  }
  return grouped;
}

/**
 * The total score: sum of capped category subtotals, clamped to `[0, 100]`.
 *
 * With the default weights summing to exactly 100 the outer clamp is unreachable, which is
 * intentional — it is a guard against a misconfigured weight table, not part of normal operation.
 */
export function computeTotalScore(
  signalsByCategory: SignalsByCategory,
  weights: CategoryWeights = DEFAULT_SCORING_CONFIG.categoryWeights,
  ceilings: SeverityCeilings = DEFAULT_SCORING_CONFIG.severityCeilings,
): TotalScore {
  const byCategory = Object.fromEntries(
    ALL_CATEGORIES.map((category) => [
      category,
      aggregateCategory(signalsByCategory[category] ?? [], weights[category], ceilings),
    ]),
  ) as Record<SignalCategory, number>;

  const sum = ALL_CATEGORIES.reduce((acc, c) => acc + byCategory[c], 0);
  return { total: Math.round(clamp(sum, 0, 100)), byCategory };
}

/** Convenience wrapper for a flat signal list. */
export function scoreSignals(
  signals: readonly SecuritySignal[],
  config: ScoringConfig = DEFAULT_SCORING_CONFIG,
): TotalScore {
  return computeTotalScore(groupByCategory(signals), config.categoryWeights, config.severityCeilings);
}

/**
 * The minimum score established by the most severe *deterministic* finding present.
 *
 * Returns 0 when nothing qualifies. `llm` signals are excluded by
 * `SCORE_FLOORS.eligibleCategories`, so a semantic verdict can never raise a floor — see
 * `config.ts` for why floors exist at all.
 */
export function severityFloor(
  signals: readonly SecuritySignal[],
  floors: typeof SCORE_FLOORS = SCORE_FLOORS,
): number {
  let floor = 0;
  for (const signal of signals) {
    if (!floors.eligibleCategories.includes(signal.category)) continue;
    // Findings borrowed from another system do not establish a floor, only our own do.
    if (floors.excludedSignalIds.includes(signal.id)) continue;
    // A signal claiming zero points is an informational note; it does not establish a floor.
    if (signal.score <= 0) continue;
    floor = Math.max(floor, floors.bySeverity[signal.severity] ?? 0);
  }
  return clamp(floor, 0, 100);
}

/** Applies the floor to an additive total. Only ever raises it. */
export function applyFloor(
  total: number,
  signals: readonly SecuritySignal[],
  floors: typeof SCORE_FLOORS = SCORE_FLOORS,
): number {
  return Math.max(clamp(total, 0, 100), severityFloor(signals, floors));
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

export function classify(
  score: number,
  thresholds: readonly { min: number; classification: Classification }[] = CLASSIFICATION_THRESHOLDS,
): Classification {
  const bounded = clamp(score, 0, 100);
  // Thresholds are ordered descending by `min`; the first match wins.
  const ordered = [...thresholds].sort((a, b) => b.min - a.min);
  for (const band of ordered) {
    if (bounded >= band.min) return band.classification;
  }
  return 'low';
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

function rank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function isAtLeast(severity: Severity, minimum: Severity): boolean {
  return rank(severity) >= rank(minimum);
}

export function lowerSeverity(severity: Severity, steps: number): Severity {
  const lowered = clamp(rank(severity) - steps, 0, SEVERITY_ORDER.length - 1);
  return SEVERITY_ORDER[lowered] ?? 'info';
}

/** Sorts signals for presentation: most severe first, then by score, then stably by id. */
export function sortSignalsForDisplay(signals: readonly SecuritySignal[]): SecuritySignal[] {
  return [...signals].sort((a, b) => {
    const bySeverity = rank(b.severity) - rank(a.severity);
    if (bySeverity !== 0) return bySeverity;
    if (b.score !== a.score) return b.score - a.score;
    return a.id.localeCompare(b.id);
  });
}
