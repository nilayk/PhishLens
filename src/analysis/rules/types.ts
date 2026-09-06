import { MAX_EVIDENCE_CHARS, collapseWhitespace, truncate } from '../../shared/text.js';
import type { SecuritySignal, Severity, SignalCategory, SignalEvidence } from '../../shared/types.js';
import type { AnalysisContext } from '../context.js';

/**
 * A detector is a pure function from normalised context to signals: no I/O, no DOM, no clock.
 * Anything a detector needs must already be on the context.
 */
export type Detect = (context: AnalysisContext) => SecuritySignal[];

export interface SignalSpec {
  id: string;
  category: SignalCategory;
  severity: Severity;
  score: number;
  title: string;
  description: string;
  evidence?: SignalEvidence;
}

/**
 * Builds a signal with all attacker-controlled strings bounded.
 *
 * Every `evidence` field can contain email content, so it is length-capped and whitespace-collapsed
 * here rather than at each of the ~40 call sites. Escaping is not needed because the UI only ever
 * assigns these to `textContent`, but bounding is: a 200 KB "evidence" string would wedge the panel.
 */
export function signal(spec: SignalSpec): SecuritySignal {
  const evidence = spec.evidence === undefined ? undefined : boundEvidence(spec.evidence);
  return {
    id: spec.id,
    category: spec.category,
    severity: spec.severity,
    score: spec.score,
    title: spec.title,
    description: spec.description,
    ...(evidence !== undefined ? { evidence } : {}),
  };
}

function boundEvidence(evidence: SignalEvidence): SignalEvidence {
  const out: SignalEvidence = {};
  if (evidence.text !== undefined) {
    out.text = truncate(collapseWhitespace(evidence.text), MAX_EVIDENCE_CHARS);
  }
  if (evidence.value !== undefined) {
    out.value = truncate(collapseWhitespace(evidence.value), MAX_EVIDENCE_CHARS);
  }
  if (evidence.url !== undefined) {
    // Kept longer than other evidence because the UI matches it against anchor hrefs to locate the
    // link in the message, and truncating would break that lookup.
    out.url = truncate(evidence.url.trim(), 2048);
  }
  return out;
}
