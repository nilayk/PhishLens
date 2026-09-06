/**
 * Aggregation is tested in isolation, before any detector is involved, on synthetic signals.
 * If these break, every score in the product is wrong.
 */
import { describe, expect, it } from 'vitest';
import {
  aggregateCategory,
  cappedSignalScore,
  classify,
  clamp,
  computeTotalScore,
  groupByCategory,
  isAtLeast,
  lowerSeverity,
  scoreSignals,
  sortSignalsForDisplay,
} from '../src/analysis/scoring/aggregate.js';
import {
  ALL_CATEGORIES,
  CATEGORY_WEIGHTS,
  SEVERITY_CEILINGS,
  totalWeight,
} from '../src/analysis/scoring/config.js';
import type { SecuritySignal, Severity, SignalCategory } from '../src/shared/types.js';

function signal(
  overrides: Partial<SecuritySignal> & { category: SignalCategory; severity: Severity; score: number },
): SecuritySignal {
  return {
    id: overrides.id ?? `test.${overrides.category}.${String(Math.random()).slice(2, 8)}`,
    title: overrides.title ?? 'Test signal',
    description: overrides.description ?? 'Synthetic signal used to exercise aggregation.',
    ...overrides,
  };
}

function many(count: number, template: Parameters<typeof signal>[0]): SecuritySignal[] {
  return Array.from({ length: count }, (_, i) => signal({ ...template, id: `test.${String(i)}` }));
}

describe('config invariants', () => {
  it('category weights sum to exactly 100', () => {
    expect(totalWeight()).toBe(100);
  });

  it('severity ceilings increase monotonically', () => {
    const order: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
    const values = order.map((s) => SEVERITY_CEILINGS[s]);
    expect(values).toEqual([...values].sort((a, b) => a - b));
    expect(new Set(values).size).toBe(values.length);
  });
});

describe('clamp', () => {
  it('bounds finite values', () => {
    expect(clamp(5, 0, 10)).toBe(5);
    expect(clamp(-3, 0, 10)).toBe(0);
    expect(clamp(99, 0, 10)).toBe(10);
  });

  it('fails closed on non-finite input, returning the minimum rather than the maximum', () => {
    // A score is a claim about risk. If a detector produces garbage we award no points instead of
    // awarding the ceiling, so a bug can never manufacture a high-risk verdict.
    expect(clamp(Number.NaN, 0, 10)).toBe(0);
    expect(clamp(Number.POSITIVE_INFINITY, 0, 10)).toBe(0);
    expect(clamp(Number.NEGATIVE_INFINITY, 0, 10)).toBe(0);
  });
});

describe('cappedSignalScore', () => {
  it('caps a single signal at its per-severity ceiling', () => {
    expect(cappedSignalScore(signal({ category: 'link', severity: 'low', score: 90 }))).toBe(
      SEVERITY_CEILINGS.low,
    );
    expect(cappedSignalScore(signal({ category: 'link', severity: 'medium', score: 90 }))).toBe(
      SEVERITY_CEILINGS.medium,
    );
    expect(cappedSignalScore(signal({ category: 'link', severity: 'info', score: 1000 }))).toBe(
      SEVERITY_CEILINGS.info,
    );
  });

  it('a lone critical signal does not exceed the critical ceiling', () => {
    const lone = signal({ category: 'identity', severity: 'critical', score: 100_000 });
    expect(cappedSignalScore(lone)).toBe(SEVERITY_CEILINGS.critical);
    expect(SEVERITY_CEILINGS.critical).toBe(100);
  });

  it('does not credit negative or non-finite scores', () => {
    expect(cappedSignalScore(signal({ category: 'link', severity: 'high', score: -50 }))).toBe(0);
    expect(cappedSignalScore(signal({ category: 'link', severity: 'high', score: Number.NaN }))).toBe(0);
  });

  it('leaves scores below the ceiling untouched', () => {
    expect(cappedSignalScore(signal({ category: 'link', severity: 'high', score: 12 }))).toBe(12);
  });
});

describe('aggregateCategory', () => {
  it('returns zero for no signals — this is the "local LLM unavailable" path', () => {
    expect(aggregateCategory([], CATEGORY_WEIGHTS.llm)).toBe(0);
    for (const category of ALL_CATEGORIES) {
      expect(aggregateCategory([], CATEGORY_WEIGHTS[category])).toBe(0);
    }
  });

  it('sums signals that fit under the weight', () => {
    const signals = [
      signal({ category: 'link', severity: 'low', score: 6 }),
      signal({ category: 'link', severity: 'low', score: 4 }),
    ];
    expect(aggregateCategory(signals, CATEGORY_WEIGHTS.link)).toBe(10);
  });

  it('many low-severity signals never exceed the category weight', () => {
    const signals = many(50, { category: 'content', severity: 'low', score: 15 });
    expect(aggregateCategory(signals, CATEGORY_WEIGHTS.content)).toBe(CATEGORY_WEIGHTS.content);
  });

  it('many info-severity signals never exceed the category weight', () => {
    const signals = many(200, { category: 'attachment', severity: 'info', score: 5 });
    expect(aggregateCategory(signals, CATEGORY_WEIGHTS.attachment)).toBe(CATEGORY_WEIGHTS.attachment);
  });

  it('a single critical signal is capped at the category weight, not the severity ceiling', () => {
    const signals = [signal({ category: 'attachment', severity: 'critical', score: 100 })];
    expect(aggregateCategory(signals, CATEGORY_WEIGHTS.attachment)).toBe(CATEGORY_WEIGHTS.attachment);
  });

  it('treats a zero weight as contributing nothing', () => {
    const signals = many(5, { category: 'llm', severity: 'critical', score: 100 });
    expect(aggregateCategory(signals, 0)).toBe(0);
  });

  it('treats a negative weight as zero rather than inverting the score', () => {
    const signals = many(5, { category: 'llm', severity: 'high', score: 50 });
    expect(aggregateCategory(signals, -20)).toBe(0);
  });

  it('is order-independent', () => {
    const signals = [
      signal({ category: 'link', severity: 'medium', score: 9 }),
      signal({ category: 'link', severity: 'info', score: 3 }),
      signal({ category: 'link', severity: 'high', score: 7 }),
    ];
    const forward = aggregateCategory(signals, CATEGORY_WEIGHTS.link);
    const backward = aggregateCategory([...signals].reverse(), CATEGORY_WEIGHTS.link);
    expect(forward).toBe(backward);
    expect(forward).toBe(19);
  });

  it('does not mutate the input array', () => {
    const signals = many(3, { category: 'link', severity: 'high', score: 30 });
    const snapshot = JSON.stringify(signals);
    aggregateCategory(signals, CATEGORY_WEIGHTS.link);
    expect(JSON.stringify(signals)).toBe(snapshot);
  });
});

describe('computeTotalScore', () => {
  it('yields zero with no signals at all', () => {
    const { total, byCategory } = computeTotalScore({});
    expect(total).toBe(0);
    for (const category of ALL_CATEGORIES) {
      expect(byCategory[category]).toBe(0);
    }
  });

  it('sums capped category subtotals', () => {
    const { total, byCategory } = computeTotalScore({
      link: [signal({ category: 'link', severity: 'medium', score: 20 })],
      identity: [signal({ category: 'identity', severity: 'low', score: 5 })],
    });
    expect(byCategory.link).toBe(20);
    expect(byCategory.identity).toBe(5);
    expect(byCategory.content).toBe(0);
    expect(total).toBe(25);
  });

  it('clamps the total to [0, 100] with many simultaneous critical signals everywhere', () => {
    const byCategory = Object.fromEntries(
      ALL_CATEGORIES.map((category) => [
        category,
        many(25, { category, severity: 'critical', score: 100 }),
      ]),
    );
    const { total } = computeTotalScore(byCategory);
    expect(total).toBe(100);
    expect(total).toBeLessThanOrEqual(100);
  });

  it('saturates each category at its own weight even when fully loaded', () => {
    const { byCategory } = computeTotalScore(
      Object.fromEntries(
        ALL_CATEGORIES.map((category) => [
          category,
          many(10, { category, severity: 'critical', score: 100 }),
        ]),
      ),
    );
    for (const category of ALL_CATEGORIES) {
      expect(byCategory[category]).toBe(CATEGORY_WEIGHTS[category]);
    }
  });

  it('never returns a negative total', () => {
    const { total } = computeTotalScore({
      link: many(4, { category: 'link', severity: 'high', score: -100 }),
    });
    expect(total).toBe(0);
  });

  it('honours an overridden weight table without touching detectors', () => {
    const signals = { link: many(3, { category: 'link', severity: 'high', score: 40 }) };
    const custom = { ...CATEGORY_WEIGHTS, link: 5 };
    expect(computeTotalScore(signals, custom).total).toBe(5);
  });

  it('returns an integer', () => {
    const { total } = computeTotalScore({
      content: [signal({ category: 'content', severity: 'medium', score: 7.4 })],
      link: [signal({ category: 'link', severity: 'medium', score: 3.3 })],
    });
    expect(Number.isInteger(total)).toBe(true);
  });
});

describe('groupByCategory', () => {
  it('always returns a bucket for every category', () => {
    const grouped = groupByCategory([signal({ category: 'link', severity: 'low', score: 1 })]);
    expect(Object.keys(grouped).sort()).toEqual([...ALL_CATEGORIES].sort());
    expect(grouped.link).toHaveLength(1);
    expect(grouped.llm).toHaveLength(0);
  });

  it('drops signals with an unrecognised category rather than mis-scoring them', () => {
    const rogue = { ...signal({ category: 'link', severity: 'high', score: 50 }), category: 'nope' };
    const grouped = groupByCategory([rogue as unknown as SecuritySignal]);
    const counted = ALL_CATEGORIES.reduce((n, c) => n + grouped[c].length, 0);
    expect(counted).toBe(0);
  });
});

describe('scoreSignals', () => {
  it('is equivalent to grouping then computing', () => {
    const signals = [
      signal({ category: 'link', severity: 'high', score: 30 }),
      signal({ category: 'content', severity: 'medium', score: 12 }),
      signal({ category: 'llm', severity: 'medium', score: 8 }),
    ];
    expect(scoreSignals(signals)).toEqual(computeTotalScore(groupByCategory(signals)));
  });
});

describe('classify', () => {
  it('maps scores to the documented bands', () => {
    expect(classify(0)).toBe('low');
    expect(classify(24)).toBe('low');
    expect(classify(25)).toBe('caution');
    expect(classify(49)).toBe('caution');
    expect(classify(50)).toBe('suspicious');
    expect(classify(74)).toBe('suspicious');
    expect(classify(75)).toBe('high-risk');
    expect(classify(100)).toBe('high-risk');
  });

  it('clamps out-of-range input', () => {
    expect(classify(-40)).toBe('low');
    expect(classify(1000)).toBe('high-risk');
    expect(classify(Number.NaN)).toBe('low');
  });
});

describe('severity helpers', () => {
  it('compares severities', () => {
    expect(isAtLeast('high', 'medium')).toBe(true);
    expect(isAtLeast('medium', 'medium')).toBe(true);
    expect(isAtLeast('low', 'medium')).toBe(false);
  });

  it('lowers severity without falling off the scale', () => {
    expect(lowerSeverity('critical', 1)).toBe('high');
    expect(lowerSeverity('medium', 1)).toBe('low');
    expect(lowerSeverity('info', 1)).toBe('info');
    expect(lowerSeverity('info', 99)).toBe('info');
  });
});

describe('sortSignalsForDisplay', () => {
  it('orders by severity, then score, then id, without mutating the input', () => {
    const input = [
      signal({ id: 'b', category: 'link', severity: 'low', score: 5 }),
      signal({ id: 'a', category: 'identity', severity: 'critical', score: 60 }),
      signal({ id: 'c', category: 'content', severity: 'low', score: 9 }),
    ];
    const snapshot = input.map((s) => s.id);
    const sorted = sortSignalsForDisplay(input);
    expect(sorted.map((s) => s.id)).toEqual(['a', 'c', 'b']);
    expect(input.map((s) => s.id)).toEqual(snapshot);
  });
});

describe('the LLM cannot dominate the score (arithmetic guarantee)', () => {
  it('a maximal semantic verdict alone stays in the "low" band', () => {
    const llmOnly = many(10, { category: 'llm', severity: 'critical', score: 100 });
    const { total } = scoreSignals(llmOnly);
    expect(total).toBe(CATEGORY_WEIGHTS.llm);
    expect(classify(total)).toBe('low');
  });

  it('the llm weight is below every classification threshold above "low"', () => {
    expect(CATEGORY_WEIGHTS.llm).toBeLessThan(25);
  });

  it('cannot subtract from a deterministic finding', () => {
    const deterministic = [signal({ category: 'link', severity: 'critical', score: 100 })];
    const withLlm = [...deterministic, signal({ category: 'llm', severity: 'info', score: 0 })];
    expect(scoreSignals(withLlm).total).toBeGreaterThanOrEqual(scoreSignals(deterministic).total);
  });
});
