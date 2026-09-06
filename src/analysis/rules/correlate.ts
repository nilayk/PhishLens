/**
 * Correlation stage: findings that require seeing signals from more than one category.
 *
 * Runs after the per-category detectors, before refinement. It exists because some of the most
 * important real-world findings are genuinely cross-category and belong in *neither* detector alone:
 *
 *   "A request to redirect salary payments" is a content observation.
 *   "The sender is an outside personal mailbox" is an identity observation.
 *   "A request to redirect salary payments, sent from an outside personal mailbox" is a different,
 *   much stronger finding than either — and it is an *identity* problem, because the sender is
 *   impersonating an employee.
 *
 * Putting this in the content detector would require it to know about domains; putting it in the
 * identity detector would require it to know about keyword themes. A correlation pass that sees both
 * keeps each detector single-purpose.
 */
import { FREEMAIL_DOMAINS } from '../../shared/public-suffix.js';
import type { SecuritySignal } from '../../shared/types.js';
import type { AnalysisContext } from '../context.js';
import { signal } from './types.js';

/** Content themes that represent a request to move money or change where money goes. */
const FINANCIAL_REQUEST_THEMES = [
  'content.wire_transfer',
  'content.payment_detail_change',
  'content.payroll_change',
  'content.gift_card',
  'content.crypto_demand',
];

function present(signals: readonly SecuritySignal[], ids: readonly string[]): boolean {
  return signals.some((s) => ids.some((id) => s.id === id || s.id.startsWith(`${id}.`)));
}

/**
 * A financial request arriving from outside the recipient's organisation, from a consumer mailbox.
 *
 * This is the core business-email-compromise shape and the single most valuable correlation the
 * engine makes. It is reported as `identity` because the substance of the finding is that the sender
 * is not who the request implies they are.
 */
function externalFinancialRequest(
  signals: readonly SecuritySignal[],
  context: AnalysisContext,
): SecuritySignal[] {
  if (!present(signals, FINANCIAL_REQUEST_THEMES)) return [];

  const recipient = context.recipientRegistrable;
  if (context.senderRegistrable === '') return [];
  // Internal mail is out of scope for this rule; so is mail to a personal address, where "outside the
  // organisation" has no meaning.
  if (recipient !== '' && recipient === context.senderRegistrable) return [];
  if (recipient !== '' && FREEMAIL_DOMAINS.has(recipient)) return [];
  if (!context.senderIsFreemail && !context.senderIsDisposable) return [];

  const target = recipient === '' ? 'the recipient organisation' : recipient;

  return [
    signal({
      id: 'identity.external_financial_request',
      category: 'identity',
      severity: 'high',
      score: 30,
      title: 'Financial request sent from an outside personal mailbox',
      description: `The message asks for money to be moved or for payment details to be changed, and it was sent from a consumer mailbox at ${context.senderRegistrable} rather than from ${target}. Requests of this kind are the mechanism of business email compromise: the wording is plausible precisely because the account it came from is real — it just does not belong to the organisation.`,
      evidence: { value: `${context.senderEmail} → ${target}` },
    }),
  ];
}

/**
 * A brand-impersonating sender that also asks for credentials. Each half is already reported; the
 * pairing is what makes it a credential-harvesting attempt rather than either alone.
 */
function impersonationWithCredentialAsk(
  signals: readonly SecuritySignal[],
  context: AnalysisContext,
): SecuritySignal[] {
  const impersonates = present(signals, [
    'identity.display_name_impersonation',
    // An organisation the brand table has never heard of impersonates just as effectively; the shape of
    // the attack does not depend on us having enumerated the victim.
    'identity.unsupported_org_claim',
    'identity.lookalike_sender_domain',
    'identity.brand_domain_in_subdomain',
    'identity.sender_punycode_domain',
    'identity.lookalike_of_recipient_domain',
  ]);
  const asksForCredentials = present(signals, [
    'content.credential_verification',
    'content.mfa_request',
    'link.credential_link_unrelated_domain',
  ]);
  if (!impersonates || !asksForCredentials) return [];

  const brandLabel = context.primaryClaim?.brand.label ?? 'a known organisation';

  return [
    signal({
      id: 'identity.impersonation_with_credential_request',
      category: 'identity',
      severity: 'critical',
      score: 40,
      title: 'Sender is impersonating a known organisation and asking for credentials',
      description: `The sender presents itself as ${brandLabel} from a domain that organisation does not control, and the message asks the recipient to sign in, confirm account details, or supply an authentication code. Those two facts together describe a credential-harvesting attempt.`,
    }),
  ];
}

/**
 * An attachment that executes code, delivered with a delivery/invoice/document pretext. The pretext
 * is what gets it opened, so the combination is worth stating.
 */
function malwarePretext(
  signals: readonly SecuritySignal[],
  context: AnalysisContext,
): SecuritySignal[] {
  const dangerousAttachment = present(signals, [
    'attachment.executable',
    'attachment.double_extension',
    'attachment.filename_direction_override',
    'attachment.script_container',
    'attachment.disk_image',
  ]);
  if (!dangerousAttachment) return [];

  const pretext =
    /\b(invoice|statement|receipt|remittance|purchase order|shipping|shipment|delivery|parcel|tracking|waybill|customs|payslip|payroll|resume|cv|scan(ned)?|voicemail|fax|contract|agreement|quotation|quote)\b/u.test(
      context.matchText,
    );
  if (!pretext) return [];

  return [
    signal({
      id: 'attachment.executable_with_document_pretext',
      category: 'attachment',
      severity: 'critical',
      score: 40,
      title: 'Executable attachment presented as a routine business document',
      description:
        'The message describes the attachment as an invoice, shipping document, or similar routine paperwork, but the attached file executes code when opened. The paperwork framing exists to make the file look expected.',
    }),
  ];
}

const correlationDetectors = [
  externalFinancialRequest,
  impersonationWithCredentialAsk,
  malwarePretext,
] as const;

export function detectCorrelatedSignals(
  signals: readonly SecuritySignal[],
  context: AnalysisContext,
): SecuritySignal[] {
  return correlationDetectors.flatMap((detect) => detect(signals, context));
}
