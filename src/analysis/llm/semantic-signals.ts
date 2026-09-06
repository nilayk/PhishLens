/**
 * Converts a `SemanticAnalysis` into `SecuritySignal`s.
 *
 * The boundary where a probabilistic opinion becomes a scored input, and therefore where "the model is
 * one input, not the truth" is actually enforced:
 *
 *  - Every signal is `category: 'llm'`, capped at that category's weight of 15. Since "caution" starts
 *    at 25, the model cannot reach even that on its own.
 *  - The conversion is **additive only**: no verdict can remove or reduce a deterministic signal, so a
 *    model injected into declaring the message safe changes nothing but its own contribution.
 *  - Sub-threshold, unsupported, and low-confidence verdicts are reported as `info` at score 0 — shown
 *    in the panel, worth nothing. `SEMANTIC_SCORING` explains why the calibration is a threshold rather
 *    than a proportional discount.
 *  - Wording is always assessment ("wording resembles…"), never observation, so the panel can separate
 *    what was measured from what was judged.
 */
import { truncate } from '../../shared/text.js';
import type { SecuritySignal, SemanticAnalysis, SemanticCategory, Severity } from '../../shared/types.js';
import { SEMANTIC_SCORING } from '../scoring/config.js';
import { signal } from '../rules/types.js';

const CATEGORY_LABELS: Readonly<Record<SemanticCategory, string>> = {
  credential_phishing: 'credential phishing',
  brand_impersonation: 'brand impersonation',
  business_email_compromise: 'business email compromise',
  malware_delivery: 'malware delivery',
  payment_fraud: 'payment fraud',
  gift_card_scam: 'a gift-card scam',
  social_engineering: 'social engineering',
  unusual_request: 'an unusual request',
  benign: 'nothing of concern',
};

/**
 * Whether the verdict actually names a concern.
 *
 * `categories` survives parsing even when the model returned none we recognise, and a rating with no
 * category has identified nothing — the panel already says so, and the score has to agree.
 */
function namesAConcern(analysis: SemanticAnalysis): boolean {
  return analysis.categories.some((c) => c !== 'benign');
}

function severityForRisk(analysis: SemanticAnalysis, corroborated: boolean): Severity {
  if (analysis.confidence < SEMANTIC_SCORING.minConfidenceForScoring) return 'info';
  if (analysis.risk < SEMANTIC_SCORING.minRiskForScoring) return 'info';
  if (!namesAConcern(analysis)) return 'info';
  // An unsupported opinion scores nothing, so it is labelled as information rather than as a finding.
  // However sure the model sounds, a severity chip beside a contribution of zero is a mixed message.
  if (!corroborated) return 'info';
  if (analysis.risk >= SEMANTIC_SCORING.highRiskThreshold) return 'high';
  if (analysis.risk >= SEMANTIC_SCORING.mediumRiskThreshold) return 'medium';
  return 'low';
}

/**
 * Raw score before capping: risk *above the dead zone*, scaled by confidence and corroboration.
 *
 * Multiplying by confidence means a hedged verdict contributes proportionally less, which is the
 * behaviour we want from a component that is explicitly not authoritative. Subtracting the dead zone
 * first is what stops an uncalibrated model from putting a few points on every clean message — see
 * `SEMANTIC_SCORING` for why that mattered enough to change the shape of the function.
 */
function rawScore(analysis: SemanticAnalysis, corroborated: boolean): number {
  if (analysis.confidence < SEMANTIC_SCORING.minConfidenceForScoring) return 0;
  if (!namesAConcern(analysis)) return 0;

  const floor = SEMANTIC_SCORING.minRiskForScoring;
  if (analysis.risk < floor) return 0;

  const scaled = (analysis.risk - floor) / (100 - floor);
  const base = scaled * analysis.confidence * SEMANTIC_SCORING.maxRawScore;
  return corroborated ? base : base * SEMANTIC_SCORING.uncorroboratedFactor;
}

/**
 * Whether any deterministic check actually found something that stands on its own.
 *
 * An `llm` signal cannot corroborate itself, and neither can a dampened one: dampening means a verified
 * sender already explains the finding, which is the opposite of independent support.
 */
function isCorroborated(deterministic: readonly SecuritySignal[]): boolean {
  return deterministic.some((s) => s.category !== 'llm' && s.score > 0 && s.dampened !== true);
}

/**
 * @param deterministic The rule-engine signals for the same message, used only to decide whether the
 * semantic verdict has technical corroboration. They are never modified, and no deterministic signal's
 * score depends on this call.
 */
export function semanticToSignals(
  analysis: SemanticAnalysis | null,
  deterministic: readonly SecuritySignal[] = [],
): SecuritySignal[] {
  if (analysis === null) return [];

  const corroborated = isCorroborated(deterministic);
  const severity = severityForRisk(analysis, corroborated);
  const score = Math.round(rawScore(analysis, corroborated));
  const sourceLabel = describeSource(analysis);

  const meaningfulCategories = analysis.categories.filter((c) => c !== 'benign');
  const categoryText =
    meaningfulCategories.length > 0
      ? meaningfulCategories.map((c) => CATEGORY_LABELS[c]).join(', ')
      : '';

  /*
   * The title is the one line most users read, so it tracks how strong the model's *claim* is, not how
   * much that claim scored. A hedged reading is softened, because "Wording resembles credential
   * phishing" on a legitimate newsletter is alarming regardless of the number beside it. A confident
   * reading that scored zero for want of corroboration keeps its strong wording — the model did say it,
   * and the description explains why it did not move the score.
   *
   * A rating in the routine band outranks the category entirely: see `routineRiskCeiling`. Reporting the
   * tag anyway would be more faithful to the response and worse for the reader, who cannot act on a
   * contradiction and would learn to disregard the section.
   */
  const routine = analysis.risk <= SEMANTIC_SCORING.routineRiskCeiling;
  const hedged =
    analysis.risk < SEMANTIC_SCORING.minRiskForScoring ||
    analysis.confidence < SEMANTIC_SCORING.minConfidenceForScoring;

  const headline =
    meaningfulCategories.length === 0 || routine
      ? 'Language analysis found nothing of concern'
      : categoryText === ''
        ? 'Wording shows signs of social engineering'
        : hedged
          ? `Wording mildly resembles ${categoryText}`
          : `Wording resembles ${categoryText}`;

  const confidenceText = `${String(Math.round(analysis.confidence * 100))}% confidence`;

  const parts = [
    `This is a language assessment by the ${sourceLabel}, not a verified technical finding.`,
    `It rated the message ${String(analysis.risk)}/100 for fraud intent at ${confidenceText}.`,
  ];

  // Say plainly why a confident-sounding rating contributed little or nothing. Without this the panel
  // shows "rated 60/100" beside a score of 0 and looks broken rather than deliberate.
  if (analysis.confidence >= SEMANTIC_SCORING.minConfidenceForScoring) {
    // Not in the routine band: there the model expressed no suspicion, and explaining away suspicion it
    // never had reads as a correction of the reader rather than of the model.
    if (!routine && analysis.risk < SEMANTIC_SCORING.minRiskForScoring) {
      parts.push(
        `Ratings below ${String(SEMANTIC_SCORING.minRiskForScoring)}/100 do not affect the score, because on ordinary mail this model reports mild suspicion far more often than it is warranted.`,
      );
    } else if (!corroborated) {
      parts.push(
        'No technical check found anything to support this reading, so it is shown for information and does not affect the score. Language analysis refines a verdict here; it does not create one on its own.',
      );
    }
  }

  if (analysis.reasons.length > 0) {
    parts.push(
      `Model's reasoning: ${analysis.reasons.map((r) => (r.endsWith('.') ? r : `${r}.`)).join(' ')}`,
    );
  }

  const signals: SecuritySignal[] = [
    signal({
      id: 'llm.assessment',
      category: 'llm',
      severity,
      score,
      title: headline,
      description: parts.join(' '),
    }),
  ];

  if (analysis.confidence < SEMANTIC_SCORING.minConfidenceForScoring && analysis.risk > 0) {
    signals.push(
      signal({
        id: 'llm.low_confidence',
        category: 'llm',
        severity: 'info',
        score: 0,
        title: 'Language assessment was inconclusive',
        description: `The ${sourceLabel} was not confident enough in its reading (${confidenceText}) for it to affect the score. It is shown only for transparency.`,
      }),
    );
  }

  return signals;
}

/**
 * Names the model that produced the reading, mid-sentence.
 *
 * A self-hosted model is named where it is known, because "your model server (qwen2.5:7b)" is checkable
 * — the reader can go and ask that model the same question — where "the model" is not. The name comes
 * from settings rather than from the response, so a model cannot choose what it is called here, and it is
 * truncated because the field tolerates 200 characters and a sentence does not.
 */
function describeSource(analysis: SemanticAnalysis): string {
  switch (analysis.source) {
    case 'local':
      return 'on-device model';
    case 'cloud':
      return 'analysis service';
    case 'server':
      return analysis.model === undefined || analysis.model === ''
        ? 'model server you configured'
        : `model server you configured (${truncate(analysis.model, 60)})`;
  }
}
