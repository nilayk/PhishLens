/**
 * Content / social-engineering detectors.
 *
 * These are deterministic keyword and shape heuristics — explicitly *not* semantic judgement. They
 * answer "does this message contain the recognisable machinery of a known scam pattern?", which is
 * a matching problem. Whether the tone is plausible in context is the LLM's job, and it lives in
 * `../llm/`.
 *
 * Two design consequences:
 *  - A pattern firing is reported as an *observation about the wording*, never as "this is a scam".
 *  - Individual patterns are cheap; the discriminating power comes from `combinations`, because
 *    "urgent" alone is noise and "urgent" + "verify your password" + a mismatched domain is not.
 */
import type { SecuritySignal, Severity } from '../../shared/types.js';
import { excerpt, firstMatch, formatList } from '../../shared/text.js';
import { hasStyledLetterforms } from '../../shared/unicode.js';
import type { AnalysisContext } from '../context.js';
import { DETECTION_TUNING } from '../scoring/config.js';
import { signal } from './types.js';

/**
 * A recognisable social-engineering theme.
 *
 * Patterns are intentionally bounded — no nested unbounded quantifiers — because they run against a
 * body that an attacker controls. `src/shared/text.ts` also truncates the body first.
 */
interface ContentPattern {
  id: string;
  title: string;
  /** Describes the *observation*, in neutral language. */
  description: string;
  severity: Severity;
  score: number;
  patterns: readonly RegExp[];
  /** How many distinct patterns must match before the theme is reported. */
  minMatches?: number;
}

const CONTENT_PATTERNS: readonly ContentPattern[] = [
  {
    id: 'urgency',
    title: 'Message creates time pressure',
    description:
      'The wording pushes for an immediate response. Urgency is used to stop the recipient pausing to check whether the request is genuine.',
    severity: 'low',
    score: 10,
    minMatches: 2,
    patterns: [
      /\b(immediate(ly)?|urgent(ly)?|right away|as soon as possible|asap|without delay|time[- ]sensitive)\b/u,
      /\b(within|in) (the next )?\d{1,2} (minute|hour|day)s?\b/u,
      /\b(expires?|expiring|expired|deadline|final notice|last (chance|warning|reminder)|act now|don'?t delay)\b/u,
      /\b(before (it'?s )?too late|failure to (do so|comply|respond)|if you (do not|don'?t) (act|respond|reply))\b/u,
      /\b(today|now)\b[^.!?]{0,40}\b(or|otherwise)\b/u,
    ],
  },
  {
    id: 'credential_verification',
    title: 'Message asks the recipient to sign in or confirm credentials',
    description:
      'The message directs the recipient to enter or confirm account credentials. A genuine provider does not need you to re-enter a password from a link in an email.',
    severity: 'medium',
    score: 24,
    patterns: [
      /\b(verify|confirm|validate|update|re-?enter|re-?confirm)\b[^.!?]{0,40}\b(your )?(account|identity|password|credentials?|login|sign[- ]?in)\b/u,
      // `details` and `information` need a qualifier naming what kind. Unqualified, they cover most of
      // ordinary business correspondence — "confirm the delivery details", "once the payment details
      // are updated", "we have updated our contact information" — none of which asks for a credential,
      // and all of which would be reported under a title claiming it did. Payment and bank wording is
      // deliberately not a qualifier here: that is a funds request, which `payment_transfer` reports
      // with the right explanation.
      /\b(verify|confirm|validate|update|re-?enter|re-?confirm)\b[^.!?]{0,40}\b(your )?(account|login|sign[- ]?in|security|password|identity|personal)\s+(details|information|info)\b/u,
      /\b(sign|log)[- ]?in\b[^.!?]{0,40}\b(to (verify|confirm|continue|avoid|restore|unlock|reactivate)|immediately|now)\b/u,
      /\b(click|tap|follow|use)\b[^.!?]{0,30}\b(link|button|here)\b[^.!?]{0,40}\b(sign|log)[- ]?in\b/u,
      /\b(your )?(password|credentials?) (will|must|needs? to) (be )?(expire|expired|expiring|updated?|changed?|reset|confirmed?|verified?)\b/u,
      // Anchored on the identity being confirmed. Bare "confirm you are" also opens "confirm you are
      // happy with your order", which is a customer-service question, not a credential ask.
      /\bconfirm (that )?(this|it) (is|was) (really )?you\b/u,
      /\bconfirm (that )?you (are|were) the\b[^.!?]{0,20}\b(account )?(holder|owner|recipient|user)\b/u,
    ],
  },
  {
    id: 'password_reset_pressure',
    title: 'Unrequested password reset or expiry notice',
    description:
      'The message announces a password change, reset, or expiry. This is a normal notification from a real provider, and also the most common pretext for a credential-harvesting page.',
    severity: 'low',
    score: 10,
    patterns: [
      /\bpassword\b[^.!?]{0,30}\b(reset|expire[sd]?|expiring|will expire|change[sd]?|update[sd]?)\b/u,
      /\b(reset|change|update) (your )?password\b/u,
      /\byour password (is|was|has been|will be)\b/u,
    ],
  },
  {
    id: 'account_threat',
    title: 'Message threatens loss of account access',
    description:
      'The message states the account will be suspended, closed, limited, or deleted. Consequence framing is used to make the recipient act before thinking.',
    severity: 'medium',
    score: 20,
    patterns: [
      /\b(account|access|profile|mailbox|subscription)\b[^.!?]{0,40}\b(suspend|suspended|suspension|terminat|deactivat|disabl|delet|lock(ed)?|restrict|limit(ed|ation)?|block(ed)?|on hold)\b/u,
      // Closure is separated from the verbs above and requires the reader's own account, because it is
      // the one that also describes a *bank* account: "my old account is being closed, use these details
      // instead" is the machinery of payment diversion, not a threat to anyone's access, and reporting it
      // as one sends the reader looking for a warning about their login that the message never made.
      // Payment diversion is not thereby missed — `payment_transfer` and `payroll_change` report it, with
      // the explanation that matches what the message actually says.
      /\byour\b[^.!?]{0,24}\b(account|access|profile|mailbox|subscription)\b[^.!?]{0,40}\bclos(e|ed|ure|ing)\b/u,
      /\bclos(e|ed|ure|ing)\b[^.!?]{0,24}\byour\b[^.!?]{0,24}\b(account|access|profile|mailbox|subscription)\b/u,
      /\b(unusual|suspicious|unauthori[sz]ed|unrecogni[sz]ed) (sign[- ]?in|login|activity|access|attempt)\b/u,
      /\b(we (have )?(detected|noticed|identified)|there (was|has been))\b[^.!?]{0,50}\b(unusual|suspicious|unauthori[sz]ed|problem|issue)\b/u,
      /\b(permanently|immediately) (delet|remov|clos|suspend|disabl)/u,
      /\bto (avoid|prevent) (the )?(suspension|deactivation|closure|deletion|termination|loss)\b/u,
    ],
  },
  {
    id: 'mfa_request',
    title: 'Message asks for a verification code',
    description:
      'The message solicits a one-time passcode or multi-factor authentication code. No legitimate organisation ever asks a customer to share one.',
    severity: 'high',
    score: 30,
    patterns: [
      /\b(share|send|provide|forward|enter|give|tell (me|us)|read (me|us))\b[^.!?]{0,40}\b(otp|one[- ]time (code|password|passcode|pin)|verification code|security code|authentication code|2fa code|mfa code|sms code|access code)\b/u,
      // "reply to this email with the verification code" — the verb and the preposition are separated.
      /\b(reply|respond|get back)\b[^.!?]{0,40}\bwith\b[^.!?]{0,40}\b(otp|one[- ]time (code|password|passcode|pin)|verification code|security code|authentication code|2fa code|mfa code|sms code|access code|code)\b/u,
      /\b(otp|verification code|security code|authentication code) (is|:)\s*\d/u,
      /\bapprove (the )?(sign[- ]?in|login|request|notification|prompt)\b[^.!?]{0,30}\b(on your (phone|device)|when (you|it) (see|receive))/u,
      /\b(mfa|2fa|two[- ]factor)\b[^.!?]{0,40}\b(re-?register|re-?enroll|reset|disable|remove|bypass)\b/u,
    ],
  },
  {
    id: 'wire_transfer',
    title: 'Message requests a funds transfer',
    description:
      'The message asks for a bank transfer or payment. Requests of this kind arriving by email are the mechanism of business email compromise.',
    severity: 'medium',
    score: 24,
    patterns: [
      /\b(wire|bank|funds?|money|payment) (transfer|transmission)\b/u,
      /\b(transfer|remit|send|release|process|initiate|authori[sz]e)\b[^.!?]{0,40}\b(\$|usd|eur|gbp|€|£)\s?[\d,]{3,}/u,
      /\b(transfer|remit|send|wire)\b[^.!?]{0,30}\b(funds?|payment|money|amount)\b/u,
      /\b(swift|iban|routing (number|code)|sort code|account (number|details))\b/u,
      /\b(beneficiary|recipient) (bank|account|details|information)\b/u,
    ],
  },
  {
    id: 'payment_detail_change',
    title: 'Message asks to change payment or banking details',
    description:
      'The message requests that stored bank or payment details be updated. Redirecting a legitimate payment stream is the highest-value form of invoice fraud.',
    severity: 'high',
    score: 30,
    patterns: [
      /\b(update|change|amend|revise|new|different|updated)\b[^.!?]{0,40}\b(bank|banking|account|payment|remittance|payee|deposit) (details|information|account|instructions|number)\b/u,
      /\b(our|the|my) (bank|banking|account) (details|information) (have|has) (changed|been (changed|updated))\b/u,
      /\b(please )?(use|note) (the )?(new|updated|following) (bank|account|payment|remittance)\b/u,
      /\bchange (of|to) (bank|banking|payment|remittance) (details|instructions)\b/u,
    ],
  },
  {
    id: 'payroll_change',
    title: 'Message requests a change to payroll or direct deposit',
    description:
      'The message asks to redirect salary or update direct-deposit details. This is a standard payroll-diversion attempt and normally belongs in an HR system, not in email.',
    severity: 'high',
    score: 30,
    patterns: [
      /\b(payroll|salary|wage|paycheck|pay ?check|direct deposit|dd) (details|information|account|change|update|deposit)\b/u,
      /\b(change|update|switch|redirect|amend)\b[^.!?]{0,40}\b(payroll|salary|direct deposit|paycheck|pay ?check|bank account for (my|the) (pay|salary))\b/u,
      /\b(my|the) (new|updated) (account|bank).{0,40}\b(payroll|salary|deposit|pay)\b/u,
      /\bwhere (my|the) (salary|pay|wages) (is|are|goes|go)\b/u,
    ],
  },
  {
    id: 'gift_card',
    title: 'Message requests gift cards or prepaid vouchers',
    description:
      'The message asks the recipient to buy gift cards or prepaid vouchers, or to send their codes. Gift cards are irreversible and untraceable, which is the entire reason they are requested.',
    severity: 'high',
    score: 32,
    // A bare mention of "gift cards" is not a request — a shop selling them says it on every
    // newsletter. Every pattern here requires an accompanying instruction to buy them or to hand
    // over their codes.
    patterns: [
      /\b(purchase|buy|get|pick up|obtain|grab|order|need|want|acquire)\b[^.!?]{0,40}\b(gift|prepaid|itunes|steam|google play|e-?gift)\b ?(cards?|vouchers?|certificates?)\b/u,
      /\b(gift|prepaid|itunes|steam|e-?gift) ?(cards?|vouchers?)\b[^.!?]{0,40}\b(worth|denomination|each|apiece|of \$?\d|at \$?\d|\$\d|\d{2,} ?(usd|eur|gbp|dollars?|pounds?|euros?))/u,
      /\b(scratch|reveal|photograph|scan|send|share|forward|snap)\b[^.!?]{0,40}\b(codes?|pins?)\b[^.!?]{0,40}\b(cards?|vouchers?)\b/u,
      /\b(cards?|vouchers?)\b[^.!?]{0,40}\b(scratch|behind|at the back|on the back)\b[^.!?]{0,30}\bcodes?\b/u,
      /\b(gift|prepaid) ?(cards?|vouchers?)\b[^.!?]{0,30}\b(today|urgently|asap|right away|immediately|before)\b/u,
    ],
  },
  {
    id: 'invoice_fraud',
    title: 'Message presents an unexpected invoice or payment demand',
    description:
      'The message asserts an outstanding invoice, overdue balance, or pending charge. Fabricated invoices are used both to extract payment and to get an attachment opened.',
    severity: 'low',
    score: 12,
    patterns: [
      /\b(invoice|inv\.?\s?#?\d|bill|statement|receipt|purchase order|po\s?#?\d)\b[^.!?]{0,40}\b(attach|enclos|overdue|outstanding|unpaid|due|past due|payment|settle)\b/u,
      /\b(overdue|outstanding|unpaid|past due|final demand)\b[^.!?]{0,30}\b(invoice|balance|amount|payment|account)\b/u,
      /\b(payment|amount) (is )?(now )?(due|overdue|required|pending|outstanding)\b/u,
      /\b(your (order|purchase|subscription|payment) (of|for)|you (have been|were) charged)\b/u,
    ],
  },
  {
    id: 'secrecy',
    title: 'Message asks the recipient to keep the request private',
    description:
      'The message asks for confidentiality or discourages discussing the request with colleagues. Isolating the recipient prevents the informal verification that would expose the fraud.',
    severity: 'medium',
    score: 24,
    patterns: [
      /\b(keep (this|it) (between us|confidential|private|discreet|quiet)|don'?t (tell|discuss|mention|share|inform)|do not (tell|discuss|mention|share|inform))\b/u,
      /\b(confidential|discreet|discretion|private) (matter|request|transaction|arrangement|deal)\b/u,
      /\b(no one|nobody) (else )?(should|needs to|must) know\b/u,
      /\b(before|until) (i|we) (announce|tell|inform|go public)\b/u,
      /\bstrictly (confidential|between)\b/u,
    ],
  },
  {
    id: 'process_bypass',
    title: 'Message asks to bypass normal procedure',
    description:
      'The message asks to skip the usual approval, verification, or procurement process, or explains why normal channels cannot be used.',
    severity: 'medium',
    score: 22,
    patterns: [
      /\b(bypass|skip|without|no need for|forget|ignore|override|circumvent)\b[^.!?]{0,40}\b(approval|authori[sz]ation|verification|procedure|process|protocol|paperwork|purchase order|usual channels?)\b/u,
      /\b(can'?t|cannot|unable to|won'?t be able to)\b[^.!?]{0,40}\b(call|phone|talk|speak|meet|be reached|answer)\b/u,
      /\b(i'?m|i am) (currently )?(in a meeting|travel(l)?ing|on a (call|flight|plane)|abroad|unavailable|tied up)\b/u,
      /\b(handle|do) (this|it) (for me|yourself)\b[^.!?]{0,30}\b(quick|fast|now|today|discreet)/u,
      /\b(email|e-?mail) (me )?(only|instead)\b/u,
    ],
  },
  {
    id: 'unusual_request_shape',
    title: 'Message opens with a vague availability check',
    description:
      'The message asks whether the recipient is available or has a moment, without stating any business. This opener is used to establish a reply before the actual request is made, so that the request never appears in the first message.',
    severity: 'medium',
    score: 20,
    minMatches: 1,
    patterns: [
      /^\s*(hi|hello|hey|good (morning|afternoon|evening))?[,\s]*(are you (available|around|at your desk|there)|do you have (a )?(minute|moment|sec)|quick (question|favou?r|task)|i need (a )?(favou?r|your help)|can you (help|assist) me)\b/u,
      /\b(are you (available|around|busy))\b[^.!?]{0,20}\?/u,
      /\bi have (a|an) (urgent|quick|small) (task|request|favou?r|matter)\b/u,
    ],
  },
  {
    id: 'crypto_demand',
    title: 'Message requests cryptocurrency',
    description:
      'The message asks for payment in cryptocurrency. Like gift cards, crypto payments are irreversible.',
    severity: 'high',
    score: 28,
    patterns: [
      /\b(bitcoin|btc|ethereum|eth|usdt|tether|crypto(currency)?|wallet address)\b[^.!?]{0,50}\b(send|transfer|pay|payment|deposit|address)\b/u,
      /\b(send|transfer|pay|deposit)\b[^.!?]{0,40}\b(bitcoin|btc|ethereum|eth|usdt|crypto)\b/u,
      /\b(bc1|[13])[a-hj-np-z0-9]{25,39}\b/u,
    ],
  },
  {
    id: 'sextortion',
    title: 'Message contains an extortion threat',
    description:
      'The message claims to possess compromising material or device access and demands payment. These claims are sent in bulk and are not backed by any actual access.',
    severity: 'high',
    score: 30,
    patterns: [
      /\b(i (have|'ve) (been )?(recorded|filmed|captured|installed)|i (have )?(full )?(access to|control of) your (device|computer|webcam|phone))\b/u,
      /\b(webcam|camera|screen) (recording|footage|video)\b[^.!?]{0,40}\b(send|release|publish|share|contacts)\b/u,
      /\b(your )?(password|passphrase) is\b[^.!?]{0,20}\b(one of|correct|right)\b/u,
      /\b(pay|send)\b[^.!?]{0,40}\b(or (i|we) (will|'ll) (send|release|publish|share|expose))\b/u,
    ],
  },
  {
    id: 'prize_lure',
    title: 'Message announces an unexpected prize or refund',
    description:
      'The message claims the recipient has won something or is owed money. An unsolicited windfall is a lure for either payment details or an advance fee.',
    severity: 'low',
    score: 12,
    patterns: [
      /\b(you (have|'ve) (won|been (selected|chosen)|qualified)|congratulations)\b[^.!?]{0,50}\b(prize|winner|lottery|reward|award|gift|selected)\b/u,
      /\b(refund|rebate|compensation|settlement|overpayment|tax return)\b[^.!?]{0,40}\b(owed|due|waiting|pending|claim|approved|eligible)\b/u,
      /\b(claim|collect|receive) (your|the) (prize|reward|refund|winnings|inheritance|funds)\b/u,
      /\bunclaimed (funds|money|balance|inheritance)\b/u,
    ],
  },
];

/**
 * Cross-pattern combinations.
 *
 * A single theme is weak evidence. A *conjunction* of themes that only co-occur in fraud is strong
 * evidence, and reporting it as one finding explains the reasoning better than two separate ones.
 */
interface Combination {
  id: string;
  requires: readonly string[];
  severity: Severity;
  score: number;
  title: string;
  description: string;
}

const COMBINATIONS: readonly Combination[] = [
  {
    id: 'urgent_credential_request',
    requires: ['urgency', 'credential_verification'],
    severity: 'high',
    score: 30,
    title: 'Message combines time pressure with a request to sign in',
    description:
      'The message both applies a deadline and asks the recipient to enter account credentials. Real providers separate these: security notices explain what happened, they do not demand a sign-in within a countdown.',
  },
  {
    id: 'threat_and_credential_request',
    requires: ['account_threat', 'credential_verification'],
    severity: 'high',
    score: 32,
    title: 'Message threatens account loss and asks for a sign-in',
    description:
      'The message states the account is at risk and directs the recipient to sign in to resolve it. This pairing is the standard structure of a credential-harvesting page lure.',
  },
  {
    id: 'gift_card_with_secrecy',
    requires: ['gift_card', 'secrecy'],
    severity: 'critical',
    score: 40,
    title: 'Message requests gift cards and asks for confidentiality',
    description:
      'The message asks for gift cards or voucher codes while also discouraging the recipient from discussing it. There is no legitimate business process with both of those properties.',
  },
  {
    id: 'urgent_gift_card_request',
    requires: ['gift_card', 'urgency'],
    severity: 'high',
    score: 32,
    title: 'Message requests gift cards under time pressure',
    description:
      'The message asks for gift cards or prepaid vouchers and presses for speed. Irreversible payment plus urgency leaves no window for the request to be checked.',
  },
  {
    id: 'payment_change_urgency',
    requires: ['payment_detail_change', 'urgency'],
    severity: 'critical',
    score: 38,
    title: 'Message urgently requests a change to payment details',
    description:
      'The message asks for banking or payment details to be changed and presses for it to happen quickly. A genuine change of banking details is never urgent, and is never communicated only by email.',
  },
  {
    id: 'bec_wire_secrecy',
    requires: ['wire_transfer', 'secrecy'],
    severity: 'critical',
    score: 40,
    title: 'Message requests a transfer and asks for confidentiality',
    description:
      'The message asks for funds to be moved while also asking the recipient not to discuss it. Confidentiality is requested specifically to prevent the verification that would stop the transfer.',
  },
  {
    id: 'wire_process_bypass',
    requires: ['wire_transfer', 'process_bypass'],
    severity: 'critical',
    score: 38,
    title: 'Message requests a transfer while asking to skip normal approval',
    description:
      'The message asks for a payment and simultaneously explains why the usual approval route or a phone confirmation cannot be used. Removing the verification step is the point of the message.',
  },
  {
    id: 'payroll_change_external',
    requires: ['payroll_change', 'process_bypass'],
    severity: 'high',
    score: 32,
    title: 'Message requests a payroll change outside the normal process',
    description:
      'The message asks for salary or deposit details to be changed and steers away from the usual HR channel.',
  },
  {
    id: 'invoice_with_urgency',
    requires: ['invoice_fraud', 'urgency'],
    severity: 'medium',
    score: 22,
    title: 'Message presses for payment of an invoice',
    description:
      'The message asserts an amount is owed and applies a deadline. Fabricated overdue invoices rely on the recipient paying rather than checking.',
  },
  {
    id: 'mfa_and_threat',
    requires: ['mfa_request', 'account_threat'],
    severity: 'critical',
    score: 38,
    title: 'Message asks for a verification code while claiming a security problem',
    description:
      'The message reports suspicious activity and asks the recipient to supply or approve an authentication code. This is how an attacker who already has the password completes a sign-in.',
  },
  {
    id: 'availability_probe_with_request',
    requires: ['unusual_request_shape', 'process_bypass'],
    severity: 'high',
    score: 28,
    title: 'Message opens with an availability check and steers away from other channels',
    description:
      'The message asks whether the recipient is free while also explaining why a call is not possible. This is the opening exchange of an impersonation attempt, before any specific request is made.',
  },
];

interface ThemeMatch {
  pattern: ContentPattern;
  matchCount: number;
  evidenceText: string;
}

function matchThemes(context: AnalysisContext): ThemeMatch[] {
  const text = context.matchText;
  const matches: ThemeMatch[] = [];

  for (const pattern of CONTENT_PATTERNS) {
    let matchCount = 0;
    let evidenceText = '';
    for (const regex of pattern.patterns) {
      const hit = firstMatch(text, regex);
      if (hit === null) continue;
      matchCount += 1;
      if (evidenceText === '') evidenceText = excerpt(text, hit.index, hit.match.length);
    }
    if (matchCount >= (pattern.minMatches ?? 1)) {
      matches.push({ pattern, matchCount, evidenceText });
    }
  }
  return matches;
}

/**
 * Bulk-mail shape.
 *
 * A marketing newsletter matches several themes ("act now", "expires", "your subscription") and has
 * dozens of links. Without recognising the shape, every newsletter scores like a phish. Detecting
 * it does not clear the message — it suppresses the *content* heuristics that bulk mail trivially
 * trips, while leaving every link and identity finding intact.
 */
function looksLikeBulkMail(context: AnalysisContext): boolean {
  // A message that pads itself with text the reader cannot see is not the legitimate marketing this
  // suppression protects, and the suppression is cheap for an attacker to earn: an unsubscribe line and a
  // link named "unsubscribe" is the entire cost. Concealed filler withdraws the benefit of the doubt.
  const hidden = context.email.hiddenText?.chars ?? 0;
  if (hidden >= DETECTION_TUNING.minHiddenBodyChars) return false;

  const unsubscribe =
    /\b(unsubscribe|opt[- ]out|manage (your )?(email )?preferences|update (your )?preferences|email preferences|no longer wish to receive|stop receiving|view (this|it) (email )?in (your )?browser|sent to you because|you are receiving this)\b/u.test(
      context.matchText,
    );
  if (!unsubscribe) return false;

  const manyLinks = context.webLinks.length >= DETECTION_TUNING.bulkMailLinkCount;
  const hasUnsubscribeLink = context.webLinks.some((l) =>
    /unsub|optout|opt-out|preferences|manage.?prefs|email.?settings/u.test(
      `${l.anchorText} ${l.target?.pathname ?? ''}`,
    ),
  );
  const credentialAsk = /\b(password|credential|verify your account|sign in to (verify|confirm)|otp|one[- ]time (code|passcode))\b/u.test(
    context.matchText,
  );

  return (manyLinks || hasUnsubscribeLink) && !credentialAsk;
}

function themeSignals(context: AnalysisContext, themes: ThemeMatch[]): SecuritySignal[] {
  const bulk = looksLikeBulkMail(context);

  return themes
    .filter((theme) => {
      // Themes that legitimate marketing mail routinely trips are dropped for bulk-shaped messages.
      if (!bulk) return true;
      return !['urgency', 'invoice_fraud', 'prize_lure', 'password_reset_pressure'].includes(
        theme.pattern.id,
      );
    })
    .map((theme) =>
      signal({
        id: `content.${theme.pattern.id}`,
        category: 'content',
        severity: theme.pattern.severity,
        score: theme.pattern.score,
        title: theme.pattern.title,
        description: theme.pattern.description,
        ...(theme.evidenceText !== '' ? { evidence: { text: theme.evidenceText } } : {}),
      }),
    );
}

function combinationSignals(themes: ThemeMatch[]): SecuritySignal[] {
  const present = new Set(themes.map((t) => t.pattern.id));
  return COMBINATIONS.filter((combo) => combo.requires.every((r) => present.has(r))).map((combo) =>
    signal({
      id: `content.combo.${combo.id}`,
      category: 'content',
      severity: combo.severity,
      score: combo.score,
      title: combo.title,
      description: combo.description,
    }),
  );
}

/**
 * A message that names a brand but whose text never references anything the recipient could
 * independently verify (an order number, an account's last four digits, a real name).
 */
function genericSalutationWithBrandClaim(context: AnalysisContext): SecuritySignal[] {
  if (context.primaryClaim === undefined) return [];
  const generic =
    /\b(dear (customer|client|user|member|sir|madam|sir\/madam|account holder|valued (customer|client|member))|dear (email )?user|hello (customer|user|member)|attention:? (customer|user)|dear [\w.+-]+@)/u;
  const hit = firstMatch(context.matchText, generic);
  if (hit === null) return [];

  return [
    signal({
      id: 'content.generic_salutation_with_brand_claim',
      category: 'content',
      severity: 'low',
      score: 10,
      title: `Message claims to be from ${context.primaryClaim.brand.label} but does not know who it is writing to`,
      description: `The greeting is generic rather than personalised. A provider that holds an account knows the account holder's name; bulk phishing does not, because the same message is sent to every address on a list.`,
      evidence: { text: excerpt(context.matchText, hit.index, hit.match.length) },
    }),
  ];
}

/**
 * The subject is formatted to get past text-based filtering rather than to be read.
 *
 * The shape, as it appears in real mail: `<RECIPIENT NAME> ❋ WELCOME TO YOUR ❋ QUOTE PLANS!❋ - A2QJZ**`.
 * None of these markers is conclusive alone — marketing shouts, and emoji in subject lines are ordinary —
 * so a signal is only raised when several coincide, and the severity follows how many.
 *
 * This is a formatting judgement about the envelope, not about meaning, which is why it is a rule and
 * not a question for the model.
 */
function subjectObfuscation(context: AnalysisContext): SecuritySignal[] {
  const subject = context.subject;
  if (subject.length < 20) return [];

  const markers: string[] = [];

  const letters = subject.replace(/[^\p{L}]/gu, '');
  if (letters.length >= DETECTION_TUNING.subjectCapsMinLetters) {
    const upper = subject.replace(/[^\p{Lu}]/gu, '').length;
    if (upper / letters.length >= DETECTION_TUNING.subjectCapsRatio) markers.push('written in capitals');
  }

  const decorative = repeatedDecorativeChar(subject);
  if (decorative !== null) markers.push(`the decorative character "${decorative}" used as a separator`);

  if (hasOpaqueCode(subject)) markers.push('an opaque tracking code');

  // Reads the subject as delivered, not the folded `matchText`, since the whole point is that these are
  // not the letters they appear to be.
  if (hasStyledLetterforms(subject)) markers.push('letters replaced by decorative substitutes');

  if (markers.length < DETECTION_TUNING.minSubjectObfuscationMarkers) return [];

  const strong = markers.length >= 3;
  return [
    signal({
      id: 'content.subject_obfuscation',
      category: 'content',
      severity: strong ? 'medium' : 'low',
      score: strong ? 14 : 8,
      title: 'Subject line is formatted to evade filtering',
      description: `The subject combines ${formatList(markers)}. These are formatting choices made to get past spam filtering and to attract attention, rather than to describe the message.`,
      evidence: { text: subject },
    }),
  ];
}

/**
 * The subject is padded with a long run of spaces.
 *
 * Hundreds of trailing spaces push the real content out of preview panes and out of the window that
 * naive subject-matching filters examine. No mail client produces this and no sender has a reason to
 * type it.
 *
 * A separate signal rather than another marker inside `subjectObfuscation` because it is far less
 * ambiguous than a caps ratio, and because it deserves its own line in the panel — "the subject is
 * padded with 700 spaces" is a concrete observation a reader can act on.
 *
 * Reads `rawSubject`: the normalised subject has had its whitespace collapsed by this point.
 */
function subjectPadding(context: AnalysisContext): SecuritySignal[] {
  // Horizontal whitespace only. Newlines in a DOM-derived string usually come from source formatting
  // rather than the header itself, and would be a false positive.
  const run = /[ \t\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]{2,}/gu;
  let longest = 0;
  for (const match of context.rawSubject.matchAll(run)) {
    longest = Math.max(longest, match[0].length);
  }
  if (longest < DETECTION_TUNING.minSubjectPaddingRun) return [];

  return [
    signal({
      id: 'content.subject_padding',
      category: 'content',
      severity: 'medium',
      score: 12,
      title: 'Subject line is padded with invisible spacing',
      description: `The subject contains a run of ${String(longest)} consecutive spaces. Padding of this kind hides the rest of the subject from message previews and from filters that only inspect the beginning of it. It serves no purpose for a reader.`,
      evidence: { text: context.subject },
    }),
  ];
}

/**
 * A decorative symbol used two or more times, as spam does to frame a subject (`❋ … ❋ … ❋`).
 *
 * Two deliberate restrictions. The range covers arrows, geometric shapes and dingbats but **not** the
 * general-punctuation block, so en dashes and bullet separators (`News • Sports • Weather`) are not
 * ornaments. And repetition is required, so a single `✅` or `🎉` in an ordinary marketing subject does
 * not count.
 */
function repeatedDecorativeChar(subject: string): string | null {
  const counts = new Map<string, number>();
  for (const char of subject) {
    if (!/[\u2190-\u2BFF]/u.test(char)) continue;
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  for (const [char, count] of counts) {
    if (count >= DETECTION_TUNING.minDecorativeRepeats) return char;
  }
  return null;
}

/**
 * An opaque alphanumeric code, e.g. `A2QJZ**` — a per-recipient campaign tag rather than anything a
 * reader needs. Requires upper case and digits with no lower case, which is what distinguishes a
 * generated tag from a word.
 */
function hasOpaqueCode(subject: string): boolean {
  for (const token of subject.split(/\s+/u)) {
    if (/[a-z]/u.test(token)) continue;
    const core = token.replace(/[^A-Z0-9]/gu, '');
    if (core.length < 5) continue;
    if (/[A-Z]/u.test(core) && /[0-9]/u.test(core)) return true;
  }
  return false;
}

/**
 * The message asserts its own trustworthiness.
 *
 * "This message was sent from a trusted sender", in the body, styled as a green-bordered system notice.
 * The claim is impersonation of a different kind from a spoofed display name: it imitates the *mail
 * client*, borrowing the authority of the one party in the exchange the reader has no reason to doubt.
 *
 * Safe to state plainly because the reasoning is airtight in both directions. No mail client puts its
 * verdict inside the message — a verdict from the message it is judging would be worthless — so any such
 * sentence was written by the sender. And a genuine sender has no reason to write it: an organisation the
 * reader already deals with does not open by insisting it is trustworthy.
 *
 * Anchored on the sender asserting *safety about this message*, not on the word "trusted" or "verified"
 * appearing. "You can trust us with your data" and "verified by our security team" are marketing.
 *
 * Virus-scanning and secure-delivery language is deliberately **not** matched, though it is the same kind
 * of sentence, because in practice it is written by legitimate senders far more often than by attackers.
 * Mail gateways append "this message has been scanned for viruses" to ordinary business mail on the way
 * out, and banks and clinics send "this is a secure message from …" from real portals. Both are useless to
 * a reader for the same reason the forged notice is — a claim inside the message about the message — but
 * the population carrying them is overwhelmingly honest, and a finding that fires on ordinary business
 * correspondence costs more than the phish it occasionally catches.
 */
function forgedTrustAssurance(context: AnalysisContext): SecuritySignal[] {
  const hit = firstMatch(context.matchText, FORGED_ASSURANCE);
  if (hit === null) return [];

  return [
    signal({
      id: 'content.forged_trust_assurance',
      category: 'content',
      severity: 'medium',
      score: 22,
      title: 'Message declares itself safe',
      description:
        'The body contains a statement that the message is trusted, verified, or has passed a security check. Notices of that kind come from your mail provider and appear outside the message; anything inside it was written by the sender, about itself. Genuine correspondence does not need to vouch for itself, and a reader who reads this as a system message has been given a verdict by the party being judged.',
      evidence: { text: excerpt(context.matchText, hit.index, hit.match.length) },
    }),
  ];
}

const FORGED_ASSURANCE =
  /\b((sent|came|comes|coming) from a (trusted|verified|known|safe) (sender|source|domain)|(verified|trusted) sender\b|(this|the) (e-?mail|message) (was |has been |is )(verified|authenticated) (as (safe|legitimate|genuine)|by (gmail|google|outlook|microsoft|your (mail|e-?mail) provider))|(this|the) (e-?mail|message) is (safe|legitimate|genuine|not (spam|phishing|a phishing (e-?mail|message))))\b/u;

/**
 * The body carries a quantity of text that CSS keeps off screen.
 *
 * A little is ordinary: nearly every marketing platform hides a one-line preheader to control what the
 * inbox preview shows, which is why this is a *volume* test and not a technique test. Past the threshold
 * it is no longer a preheader — it is the filter-evasion pattern of pasting paragraphs of unrelated prose
 * into a message so that the ratio of suspicious wording to ordinary wording comes out looking innocent.
 *
 * The extension is one of the systems that dilutes, which is why the extraction separates this text
 * rather than merely noticing it. See `HiddenText`.
 */
function hiddenBodyText(context: AnalysisContext): SecuritySignal[] {
  const hidden = context.email.hiddenText;
  if (hidden === undefined || hidden.chars < DETECTION_TUNING.minHiddenBodyChars) return [];

  const how = hidden.techniques.length > 0 ? ` using ${formatList(hidden.techniques)}` : '';
  return [
    signal({
      id: 'content.hidden_body_text',
      category: 'content',
      severity: 'medium',
      score: 22,
      title: 'Message contains a large amount of text you cannot see',
      description: `About ${String(hidden.chars)} characters of the body are hidden from view${how}. Senders hide a single line to control the inbox preview; text at this length is there to be read by filters rather than by you, and padding a message with unrelated prose is how the proportion of suspicious wording in it is made to look ordinary.`,
      evidence: { value: `${String(hidden.chars)} hidden characters` },
    }),
  ];
}

export function detectContentSignals(context: AnalysisContext): SecuritySignal[] {
  const themes = matchThemes(context);
  return [
    ...themeSignals(context, themes),
    ...combinationSignals(themes),
    ...genericSalutationWithBrandClaim(context),
    ...subjectObfuscation(context),
    ...subjectPadding(context),
    ...forgedTrustAssurance(context),
    ...hiddenBodyText(context),
  ];
}

export const __testables = { CONTENT_PATTERNS, COMBINATIONS, matchThemes, repeatedDecorativeChar };
