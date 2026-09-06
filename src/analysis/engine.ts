/**
 * The analysis pipeline, split into two entry points so that "the LLM is optional" is structural rather
 * than a promise:
 *
 *  - `analyzeDeterministic()` — pure and synchronous. No I/O, no Chrome, no DOM, no clock beyond one
 *    injected timestamp. It produces a complete, classified result on its own, and it is what the test
 *    suite exercises against fixtures.
 *  - `analyze()` — the same thing, plus at most the semantic category's weight folded on top.
 *
 * The deterministic result is the product, not a degraded mode.
 */
import type {
  AnalysisResult,
  EmailMessage,
  SecuritySignal,
  SemanticAnalysis,
  SemanticAnalyzer,
  SemanticSource,
  SemanticStatus,
} from '../shared/types.js';
import { isAborted } from '../shared/abort.js';
import { logger } from '../shared/logger.js';
import { buildContext, type AnalysisContext } from './context.js';
import { semanticToSignals } from './llm/semantic-signals.js';
import { runRuleEngine } from './rules/index.js';
import {
  applyFloor,
  classify,
  groupByCategory,
  computeTotalScore,
  sortSignalsForDisplay,
} from './scoring/aggregate.js';
import { DEFAULT_SCORING_CONFIG, type ScoringConfig } from './scoring/config.js';

declare const __PHISHLENS_VERSION__: string;

export const ENGINE_VERSION =
  typeof __PHISHLENS_VERSION__ === 'undefined' ? '0.0.0-dev' : __PHISHLENS_VERSION__;

export interface DeterministicOptions {
  config?: ScoringConfig;
  /** Injected so results are reproducible in tests. */
  now?: number;
}

export interface AnalyzeOptions extends DeterministicOptions {
  /** Forwarded to the analyzer so a superseded message stops occupying the model. */
  signal?: AbortSignal;
}

export interface DeterministicResult extends AnalysisResult {
  /** Retained for the UI's highlighting and for the semantic stage; never serialised anywhere. */
  context: AnalysisContext;
}

/**
 * The full deterministic analysis. Pure: same input, same output.
 */
export function analyzeDeterministic(
  email: EmailMessage,
  options: DeterministicOptions = {},
): DeterministicResult {
  const config = options.config ?? DEFAULT_SCORING_CONFIG;
  const context = buildContext(email);
  const signals = runRuleEngine(context);

  return {
    ...buildResult(signals, config, options.now ?? Date.now(), 'none'),
    context,
  };
}

/**
 * Deterministic analysis plus an optional semantic verdict.
 *
 * The semantic stage cannot fail the analysis: if the analyzer is unavailable, throws, times out, or
 * returns something that does not validate, the deterministic result is returned unchanged with
 * `semanticSource: 'none'` and zero `llm` contribution.
 */
export async function analyze(
  email: EmailMessage,
  analyzer: SemanticAnalyzer | null,
  options: AnalyzeOptions = {},
): Promise<AnalysisResult> {
  const config = options.config ?? DEFAULT_SCORING_CONFIG;
  const deterministic = analyzeDeterministic(email, options);

  if (analyzer === null) return withSemanticStatus(stripContext(deterministic), 'off');

  const semantic = await runSemanticSafely(analyzer, email, options.signal);
  if (semantic.analysis === null) {
    return withSemanticStatus(stripContext(deterministic), semantic.status);
  }

  // The deterministic signals are passed in so the semantic layer knows whether anything checkable
  // supports its reading. They are inputs to *its* weighting only; none of them is altered.
  const combined = [
    ...deterministic.signals,
    ...semanticToSignals(semantic.analysis, deterministic.signals),
  ];
  return {
    ...withSemanticStatus(
      buildResult(combined, config, options.now ?? Date.now(), semantic.analysis.source),
      'ready',
    ),
    semantic: semantic.analysis,
  };
}

interface SemanticOutcome {
  analysis: SemanticAnalysis | null;
  /** Never `pending` or `off`: this describes an attempt that has already finished. */
  status: Exclude<SemanticStatus, 'pending' | 'off'>;
}

/**
 * Runs the analyzer such that no failure mode reaches the caller.
 *
 * `isAvailable()` is contractually non-throwing, but this does not rely on adapters honouring their
 * contract — an unstable browser API is exactly where one gets broken.
 *
 * The statuses are kept apart because they mean different things downstream: `unavailable` describes
 * the browser and is permanent, `no-output` and `error` describe this one message, and `cancelled`
 * describes only the reader navigating away. The card words them differently and only some may be
 * cached, so collapsing them here would make both impossible.
 */
async function runSemanticSafely(
  analyzer: SemanticAnalyzer,
  email: EmailMessage,
  signal?: AbortSignal,
): Promise<SemanticOutcome> {
  try {
    if (!(await analyzer.isAvailable())) return { analysis: null, status: 'unavailable' };
  } catch (error) {
    logger.debug('semantic availability check threw', error);
    return { analysis: null, status: 'unavailable' };
  }

  try {
    const analysis = await analyzer.analyze(email, signal === undefined ? {} : { signal });
    if (analysis !== null) return { analysis, status: 'ready' };
    // A cancelled attempt also resolves to null. Calling that "the model declined to answer" is both
    // untrue and sticky, since the caller keeps settled outcomes for the session.
    return { analysis: null, status: isAborted(signal) ? 'cancelled' : 'no-output' };
  } catch (error) {
    // An abort surfaces as a rejection in most adapters, and is not a failure of the model.
    if (isAborted(signal)) return { analysis: null, status: 'cancelled' };
    logger.debug('semantic analysis threw', error);
    return { analysis: null, status: 'error' };
  }
}

/**
 * Whether the semantic stage reached an answer worth keeping for the rest of the session.
 *
 * The guard on what callers may cache. Only `ready` (the model answered) and `off` (it was deliberately
 * not asked) are conclusions about the message; the rest describe a moment — a model still downloading,
 * a timeout, an attempt cut short by navigation — and caching a moment makes it permanent.
 */
export function isSemanticSettled(status: SemanticStatus | undefined): boolean {
  return status === 'ready' || status === 'off';
}

/** Records how the semantic stage ended, without touching anything the rule engine decided. */
export function withSemanticStatus(result: AnalysisResult, status: SemanticStatus): AnalysisResult {
  return { ...result, meta: { ...result.meta, semanticStatus: status } };
}

function buildResult(
  signals: SecuritySignal[],
  config: ScoringConfig,
  now: number,
  semanticSource: SemanticSource,
): AnalysisResult {
  const { total, byCategory } = computeTotalScore(
    groupByCategory(signals),
    config.categoryWeights,
    config.severityCeilings,
  );
  // A conclusive deterministic finding establishes a minimum, so a single-dimension attack is not
  // diluted by the categories it happens not to touch. See scoring/config.ts `SCORE_FLOORS`.
  const score = applyFloor(total, signals);

  return {
    score,
    classification: classify(score, config.thresholds),
    signals: sortSignalsForDisplay(signals),
    categoryScores: byCategory,
    meta: {
      analyzedAt: now,
      engineVersion: ENGINE_VERSION,
      semanticSource,
    },
  };
}

function stripContext(result: DeterministicResult): AnalysisResult {
  const { context: _context, ...rest } = result;
  return rest;
}

/** Signals that represent a *proven* observation rather than a probabilistic assessment. */
export function observedSignals(result: AnalysisResult): SecuritySignal[] {
  return result.signals.filter((s) => s.category !== 'llm');
}

/** Signals that represent an AI assessment. Rendered separately and labelled as such. */
export function assessmentSignals(result: AnalysisResult): SecuritySignal[] {
  return result.signals.filter((s) => s.category === 'llm');
}
