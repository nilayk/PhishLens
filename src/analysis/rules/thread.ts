/**
 * Conversation-context detectors: *did this reply come from someone already in the thread?*
 *
 * Every other detector judges a message in isolation, which is precisely the blind spot reply-chain
 * hijacking exploits. The attacker answers into a real conversation — often one they can see because a
 * participant's mailbox is compromised — so the quoted history is genuine, the subject is a legitimate
 * `Re:`, the tone matches, and there is nothing anomalous to find in the message by itself. What gives it
 * away is the sender: a party that was not in the conversation until the moment money or credentials
 * were discussed, wearing a name or a domain that resembles one that was.
 *
 * These rules deliberately do **not** fire on a merely unfamiliar sender. People are added to threads
 * constantly — a colleague is looped in, a vendor hands over to a different rep, a ticket system answers
 * from a new address — so "new domain in this thread" on its own would fire on ordinary correspondence
 * every day. Only *resemblance* to an established party is reported, because resemblance is the part
 * that has no innocent explanation: there is no reason for a legitimate new participant's domain to be
 * one character away from an existing one.
 */
import type { SecuritySignal } from '../../shared/types.js';
import { domainCore, sameRegistrableDomain } from '../../shared/url.js';
import { decodeIdnHost, editDistance, skeleton } from '../../shared/unicode.js';
import type { AnalysisContext, ThreadParty } from '../context.js';
import { DETECTION_TUNING } from '../scoring/config.js';
import { signal } from './types.js';

/**
 * The sender's domain is a near-miss of a domain already in the conversation.
 *
 * The highest-value signal in this file: `northwind-supply.com` has been in the thread for six
 * messages, and the reply asking for changed bank details comes from `northwlnd-supply.com`. Nothing
 * else in the engine can see this, because the imitated domain is not a famous brand — it is whoever
 * this particular reader happens to do business with, which no curated table could contain.
 */
function lookalikeThreadParticipant(
  context: AnalysisContext,
  match: ParticipantLookalikeMatch | null,
): SecuritySignal[] {
  if (match === null) return [];

  const confusable = match.kind === 'confusable';
  return [
    signal({
      id: 'identity.thread_lookalike_participant',
      category: 'identity',
      severity: confusable ? 'critical' : 'high',
      score: confusable ? 45 : 32,
      title: 'Sender domain imitates another participant in this conversation',
      description: confusable
        ? `Earlier messages in this thread came from ${match.party.registrable}. This one was sent from ${context.senderRegistrable}, which is written with characters chosen to look identical to it but is a different domain under someone else's control. Replying, or acting on any instruction here, sends it to the wrong party.`
        : `Earlier messages in this thread came from ${match.party.registrable}. This one was sent from ${context.senderRegistrable}, which differs by ${match.distance === 1 ? 'a single character' : `${String(match.distance)} characters`} and is a different domain. Check the sender against an earlier message in the thread before replying.`,
      evidence: { value: `${context.senderRegistrable} vs ${match.party.registrable}` },
    }),
  ];
}

/**
 * The sender uses the display name of someone already in the conversation, from a different domain.
 *
 * The version of the same attack that needs no lookalike domain: keep "Maria Delgado" in the From
 * name, send from any mailbox at all, and rely on the mail client showing the name rather than the
 * address. Gmail shows the name.
 *
 * `high` rather than `critical`, because this has a real innocent explanation that the domain rule does
 * not: someone replying from their phone, their personal address, or a new employer genuinely keeps
 * their own name. It is worth a warning, not a verdict on its own.
 */
function threadParticipantNameReuse(
  context: AnalysisContext,
  lookalike: ParticipantLookalikeMatch | null,
): SecuritySignal[] {
  if (context.senderName === '') return [];

  // A hijack by lookalike domain almost always keeps the name too, and reporting both says one thing
  // twice. The domain finding is the more useful of the two — it names what the reader can compare — so
  // it stands alone.
  if (lookalike !== null) return [];

  const senderKey = skeleton(context.senderName);
  if (senderKey.length < DETECTION_TUNING.minThreadNameChars) return [];
  if (isRoleName(context.senderName)) return [];

  const impersonated = context.priorParties.find(
    (party) =>
      party.nameKey === senderKey &&
      party.email !== '' &&
      party.email !== context.senderEmail &&
      // Same organisation, different mailbox, is how a person's own mail legitimately varies.
      !sameRegistrableDomain(party.registrable, context.senderRegistrable),
  );
  if (impersonated === undefined) return [];

  return [
    signal({
      id: 'identity.thread_participant_name_reuse',
      category: 'identity',
      severity: 'high',
      score: 30,
      title: `Sender uses a participant's name from a different address`,
      description: `"${context.senderName}" already appears in this conversation as ${impersonated.email}, but this message was sent from ${context.senderEmail}, which is not on the same domain. Mail clients show the name and hide the address, so a reply that keeps the name while changing the mailbox reads as coming from the same person.`,
      evidence: { text: context.senderName, value: `${context.senderEmail} vs ${impersonated.email}` },
    }),
  ];
}

export interface ParticipantLookalikeMatch {
  party: ThreadParty;
  kind: 'confusable' | 'edit-distance';
  distance: number;
}

/**
 * Compares a domain against the domains already in a conversation.
 *
 * Deliberately narrower than the brand comparison in `identity.ts`. That one may treat the same name
 * under a different suffix as an imitation, because a brand's real domains are enumerated and
 * `paypal.co` is demonstrably not one of them. Here nothing is enumerated: a thread containing
 * `example.com` says nothing about whether the same company also uses `example.de`, and companies
 * routinely reply from a country domain, an acquired brand's domain, or a separate transactional one.
 * So an identical name under a different suffix is **not** reported, and only a difference in the name
 * itself — the part a reader actually compares — counts.
 */
export function findParticipantLookalike(
  senderRegistrable: string,
  parties: readonly ThreadParty[],
): ParticipantLookalikeMatch | null {
  const senderCore = domainCore(decodeIdnHost(senderRegistrable));
  const senderSkeleton = skeleton(senderCore);
  if (senderSkeleton.length < DETECTION_TUNING.minThreadDomainCoreChars) return null;

  let best: ParticipantLookalikeMatch | null = null;

  for (const party of parties) {
    if (party.registrable === '' || party.registrable === senderRegistrable) continue;

    const partyCore = domainCore(decodeIdnHost(party.registrable));
    const partySkeleton = skeleton(partyCore);
    if (partySkeleton.length < DETECTION_TUNING.minThreadDomainCoreChars) continue;

    // Same name, different suffix: `example.com` and `example.de`. Usually one organisation, so this
    // is the case the rule stays silent about.
    if (senderCore === partyCore) continue;

    if (senderSkeleton === partySkeleton) {
      return { party, kind: 'confusable', distance: 0 };
    }

    const distance = editDistance(
      senderSkeleton,
      partySkeleton,
      DETECTION_TUNING.lookalikeMaxEditDistance,
    );
    if (distance > DETECTION_TUNING.lookalikeMaxEditDistance) continue;

    // Two edits only mean something on a name long enough that unrelated words do not collide.
    if (distance > 1 && Math.min(senderSkeleton.length, partySkeleton.length) < 8) continue;

    if (best === null || distance < best.distance) {
      best = { party, kind: 'edit-distance', distance };
    }
  }

  return best;
}

/**
 * Names that identify a function rather than a person.
 *
 * Reused across unrelated organisations by design, so matching on them would report every thread where
 * two companies both answer from a desk called "Support".
 */
const ROLE_NAMES: ReadonlySet<string> = new Set([
  'support',
  'info',
  'team',
  'sales',
  'billing',
  'accounts',
  'admin',
  'help',
  'helpdesk',
  'service',
  'customerservice',
  'noreply',
  'donotreply',
  'notifications',
  'security',
  'it',
  'hr',
  'payroll',
  'finance',
]);

function isRoleName(name: string): boolean {
  const folded = skeleton(name);
  if (ROLE_NAMES.has(folded)) return true;
  // "Acme Support" is still a desk, not a person, so a trailing role word disqualifies the name too.
  const words = name.split(/\s+/u).map((word) => skeleton(word));
  const last = words[words.length - 1] ?? '';
  return words.length <= 2 && ROLE_NAMES.has(last);
}

/**
 * Both rules need the same comparison against the conversation, and the second needs to know whether
 * the first fired, so the match is computed once here rather than by each rule independently.
 */
export function detectThreadSignals(context: AnalysisContext): SecuritySignal[] {
  if (!context.inThread || context.senderRegistrable === '') return [];
  // A sender already established in the thread is the opposite of an intruder.
  const established = context.priorRegistrables.has(context.senderRegistrable);
  const lookalike = established
    ? null
    : findParticipantLookalike(context.senderRegistrable, context.priorParties);

  return [
    ...lookalikeThreadParticipant(context, lookalike),
    ...threadParticipantNameReuse(context, lookalike),
  ];
}
