/**
 * Gmail DOM → `EmailMessage`.
 *
 * Extraction discipline:
 *  - **Every field is independently `try`-wrapped.** A Gmail redesign that breaks attachment chips
 *    degrades to "no attachment signals"; it does not break sender extraction or the whole extension.
 *  - **Read-only.** Nothing here writes to Gmail's DOM, adds listeners to Gmail's elements, or
 *    re-parents anything.
 *  - **`textContent` only.** No `innerHTML` read that could be re-inserted anywhere, no HTML parsing
 *    of message content. Body text is truncated at the boundary so the rest of the system never sees
 *    an unbounded string.
 *  - **Quoted text is removed** before the body is read, so a reply is analysed on what was newly
 *    written rather than re-analysing the message it quotes.
 */
import { logger } from '../shared/logger.js';
import { MAX_BODY_CHARS, collapseWhitespace, emailDomain, fileExtension, parseMailbox, truncate } from '../shared/text.js';
import type {
  AuthVerdict,
  EmailAttachment,
  EmailAuthInfo,
  EmailLink,
  EmailMessage,
  RawFields,
} from '../shared/types.js';
import { normalizeDomain, parseUrl } from '../shared/url.js';
import type { MailAdapter, MessageHandle } from './adapter.js';
import { SELECTORS, queryAll, queryAllUnion, queryFirst } from './selectors.js';

/** Upper bound on links extracted from one message. A hostile message can contain thousands. */
const MAX_LINKS = 300;
const MAX_ATTACHMENTS = 60;

/** Runs an extraction step, returning a fallback if it throws for any reason. */
function attempt<T>(label: string, fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch (error) {
    logger.debug(`extraction step failed: ${label}`, error);
    return fallback;
  }
}

export class GmailDomAdapter implements MailAdapter {
  readonly id = 'gmail-dom';

  observationRoot(): Element | null {
    return queryFirst(document, SELECTORS.conversationRoot);
  }

  /**
   * The thread id from the URL hash, e.g. `#inbox/FMfcgzQb...` → `FMfcgzQb...`.
   *
   * Read from the route rather than the DOM on purpose: this is the signal that tells us *which*
   * thread should be on screen, and cross-checking it against the DOM is what prevents a stale
   * analysis when Gmail has navigated but not yet re-rendered. See `observer.ts`.
   */
  routeThreadId(): string {
    try {
      const hash = window.location.hash.replace(/^#/u, '');
      if (hash === '') return '';
      const segments = hash.split('/').filter((s) => s !== '');
      const last = segments[segments.length - 1] ?? '';
      // A thread id is a long opaque token; `#inbox`, `#inbox/p2`, `#search/foo` are not threads.
      return /^[A-Za-z0-9_-]{16,}$/u.test(last) ? last : '';
    } catch {
      return '';
    }
  }

  /**
   * The message the user is reading: the last *expanded* message in the open thread that the user did
   * not write themselves.
   *
   * Gmail collapses all but the most recent message in a conversation, so the last expanded one is
   * normally what is on screen and being read. The exception is a thread the user has replied to: their
   * own reply is then the newest message and the one Gmail leaves expanded, so taking the last expanded
   * message assessed the user's own outgoing mail, scoring their writing while the received message a
   * warning might matter for sat collapsed above it. Skipping their own messages puts the assessment
   * back on the received mail in the thread, and makes expanding an older received message work.
   *
   * When every expanded message is the user's own, this returns `null` and no badge is shown. There is
   * nothing inbound on screen to assess, and a verdict on your own reply is noise at best.
   */
  currentMessage(): MessageHandle | null {
    return attempt<MessageHandle | null>(
      'currentMessage',
      () => {
        const root = this.observationRoot() ?? document.body;
        const candidates = queryAllUnion(root, SELECTORS.messageContainer).filter((element) =>
          isExpanded(element),
        );

        const index = selectReadableMessage(
          candidates.map((candidate) => readIdentity(candidate)),
          readAccountAddress() ?? '',
          isOutboundLabel(window.location.hash),
        );
        const element = index === null ? undefined : candidates[index];
        if (element === undefined) return null;

        const bodyElement = queryFirst(element, SELECTORS.body);
        // A message container with no readable body is a collapsed or still-loading row.
        if (bodyElement === null) return null;

        return {
          messageId: readMessageId(element),
          threadId: readThreadId(),
          headerElement: findHeaderAnchorPoint(element),
          bodyElement,
          root: element,
        };
      },
      null,
    );
  }

  extract(handle: MessageHandle): EmailMessage {
    const sender = attempt('sender', () => extractSender(handle.root), {});
    const bodyText = attempt('body', () => extractBodyText(handle.bodyElement), '');
    const auth = attempt<EmailAuthInfo | undefined>('auth', () => extractAuth(handle.root), undefined);
    const raw = attempt<RawFields>('raw', () => {
      const original = rawSubject();
      const collapsed = collapseWhitespace(original);
      return {
        // Only carried when normalisation actually removed something, so the raw slot stays a signal
        // that there is something to look at rather than a duplicate of every field.
        ...(sender.rawEmail !== undefined && sender.rawEmail !== sender.email
          ? { senderEmail: sender.rawEmail }
          : {}),
        ...(original !== collapsed ? { subject: original } : {}),
      };
    }, {});

    return {
      ...(sender.name !== undefined ? { senderName: sender.name } : {}),
      ...(sender.email !== undefined ? { senderEmail: sender.email } : {}),
      ...(sender.replyTo !== undefined ? { replyTo: sender.replyTo } : {}),
      ...(sender.recipient !== undefined ? { recipientEmail: sender.recipient } : {}),
      subject: attempt('subject', () => extractSubject(), ''),
      bodyText,
      links: attempt('links', () => extractLinks(handle.bodyElement), []),
      attachments: attempt('attachments', () => extractAttachments(handle.root), []),
      ...(auth !== undefined ? { auth } : {}),
      ...(handle.messageId !== '' ? { messageId: handle.messageId } : {}),
      ...(handle.threadId !== '' ? { threadId: handle.threadId } : {}),
      ...(Object.keys(raw).length > 0 ? { raw } : {}),
    };
  }
}

// ---------------------------------------------------------------------------
// Which message in the thread to assess
// ---------------------------------------------------------------------------

/** Just enough about a message to decide whether the user wrote it. */
export interface MessageIdentity {
  /** Lowercased sender address, or `''` when the header did not yield one. */
  sender: string;
  /**
   * Lowercased addresses the header names outside the sender element — in practice the recipient row —
   * or `null` when it named none.
   *
   * `null` means **unknown**, not "nobody". Gmail may not have rendered the recipient row yet, and the
   * distinction decides which way the ambiguity falls: an unknown audience is treated as inbound and
   * assessed, because a missed assessment is the more dangerous of the two mistakes.
   *
   * The account's own address is deliberately *kept* when it appears here. It is what separates "from
   * me, to Alice" (a message I sent) from "from me, to me" (a forgery addressed back at me), so
   * filtering it out as redundant with the sender would silently defeat the check.
   */
  audience: string[] | null;
}

/**
 * Whether this is a message the user sent, as opposed to one that merely claims to be from them.
 *
 * The distinction is the whole difficulty. "From address equals the account address" is *not* enough on
 * its own, because a message forged to appear as if it came from the reader's own address is a scam
 * genre in its own right ("I have access to your account, pay me"), it arrives in the inbox, and Gmail
 * displays it as being from "me" exactly as it displays a real sent message. Suppressing on the address
 * alone would hand that genre a guaranteed pass.
 *
 * So a message counts as outbound only when it is from the account **and addressed to someone else**:
 *  - A reply the user wrote is from them and names the other party as recipient → outbound.
 *  - A forgery addressed back to the reader names the account among the recipients → not outbound.
 *  - A forgery that names nobody at all leaves the audience unknown → not outbound.
 *
 * Known residual gap: a forgery from the reader's own address, addressed to a third party and delivered
 * to the reader by Bcc, is indistinguishable from a real sent message by anything visible in the DOM,
 * and is treated as outbound. Gmail presents it as the reader's own message too.
 */
export function isOutboundMessage(identity: MessageIdentity, account: string): boolean {
  if (account === '' || identity.sender !== account) return false;
  const { audience } = identity;
  if (audience === null || audience.length === 0) return false;
  return !audience.includes(account);
}

/**
 * Index of the message to assess: the last one the user did not write. `null` when there is none.
 *
 * Searched newest-first, so a thread ending in the user's reply falls back to the inbound message above
 * it rather than to the oldest message in the thread.
 */
export function selectReadableMessage(
  identities: readonly MessageIdentity[],
  account: string,
  outboundView: boolean,
): number | null {
  // In Sent or Drafts every message is the user's own by construction, whatever the headers show. This
  // is checked separately because the route cannot be influenced by a sender: nothing a phisher does
  // puts their message under `#sent`.
  if (outboundView) return null;

  for (let index = identities.length - 1; index >= 0; index -= 1) {
    const identity = identities[index];
    if (identity !== undefined && !isOutboundMessage(identity, account)) return index;
  }
  return null;
}

/** Whether the route names a folder that holds only the user's own mail. */
export function isOutboundLabel(hash: string): boolean {
  const label = hash.replace(/^#/u, '').split(/[/?]/u)[0]?.toLowerCase() ?? '';
  return label === 'sent' || label === 'drafts';
}

/**
 * The signed-in address from the document title, which Gmail formats as
 * `<subject or folder> - <account> - Gmail`.
 *
 * Positional rather than a search for the first address in the string: a subject line can contain an
 * email address, and picking that one would make the reader's own mail look like someone else's.
 */
export function accountAddressFromTitle(title: string): string | undefined {
  const parts = title.split(' - ');
  const candidate = parts[parts.length - 2]?.trim() ?? '';
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(candidate) ? candidate.toLowerCase() : undefined;
}

function readIdentity(element: Element): MessageIdentity {
  return attempt<MessageIdentity>(
    'identity',
    () => {
      const senderElement = queryFirst(element, SELECTORS.senderSpan);
      const sender =
        senderElement?.getAttribute('email')?.trim().toLowerCase() ??
        parseMailbox(collapseWhitespace(queryFirst(element, SELECTORS.senderTextual)?.textContent ?? ''))
          .email ??
        '';

      return { sender, audience: readAudience(element, senderElement) };
    },
    // An unreadable header is an unknown one, which `isOutboundMessage` treats as inbound.
    { sender: '', audience: null },
  );
}

/**
 * Addresses the header names besides the sender's own.
 *
 * Two exclusions carry weight:
 *
 *  - **The body is skipped.** Message bodies are attacker-controlled, and an `email` attribute is a
 *    single span away. Scanning the whole message would let a forged message add a recipient of its own
 *    invention, turn itself into "from you, to someone else", and suppress its own assessment.
 *  - **The sender element and everything around it.** Gmail may carry the sender's address on the
 *    element, on a wrapper, or on a nested node; counting any of those as an audience member would make
 *    a real reply look self-addressed and undo the skip.
 */
function readAudience(element: Element, senderElement: Element | null): string[] | null {
  const bodies = queryAllUnion(element, SELECTORS.body);
  const found = new Set<string>();

  for (const node of queryAllUnion(element, SELECTORS.addressCarrier)) {
    if (bodies.some((body) => body === node || body.contains(node))) continue;
    if (senderElement !== null && (senderElement.contains(node) || node.contains(senderElement))) {
      continue;
    }

    const raw =
      node.getAttribute('email')?.trim() ?? node.getAttribute('data-hovercard-id')?.trim() ?? '';
    const address = raw.toLowerCase();
    if (address === '' || !address.includes('@')) continue;
    found.add(address);
  }

  return found.size === 0 ? null : [...found];
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

interface SenderFields {
  name?: string;
  email?: string;
  /** The address with its original case, kept because randomised case is itself a signal. */
  rawEmail?: string;
  replyTo?: string;
  recipient?: string;
}

function extractSender(root: Element): SenderFields {
  const fields: SenderFields = {};

  const span = queryFirst(root, SELECTORS.senderSpan);
  if (span !== null) {
    const rawEmail = span.getAttribute('email')?.trim();
    if (rawEmail !== undefined && rawEmail !== '') {
      fields.rawEmail = truncate(rawEmail, 320);
      fields.email = rawEmail.toLowerCase();
    }

    const name = span.getAttribute('name')?.trim() ?? collapseWhitespace(span.textContent);
    // Gmail sometimes puts the address itself in the name slot; that is not a display name.
    if (name !== '' && name !== fields.email) fields.name = truncate(name, 300);
  }

  if (fields.email === undefined) {
    const textual = queryFirst(root, SELECTORS.senderTextual);
    if (textual !== null) {
      const parsed = parseMailbox(collapseWhitespace(textual.textContent));
      if (parsed.email !== undefined) fields.email = parsed.email;
      if (parsed.name !== undefined && fields.name === undefined) {
        fields.name = truncate(parsed.name, 300);
      }
    }
  }

  const details = extractDetailRows(root);
  const replyTo = details.get('reply-to');
  if (replyTo !== undefined) {
    const parsed = parseMailbox(replyTo);
    if (parsed.email !== undefined) fields.replyTo = parsed.email;
  }

  const to = details.get('to');
  if (to !== undefined) {
    const parsed = parseMailbox(to.split(',')[0] ?? '');
    if (parsed.email !== undefined) fields.recipient = parsed.email;
  }
  fields.recipient ??= readAccountAddress();

  return fields;
}

/**
 * Reads Gmail's "show details" table into a `label → value` map.
 *
 * The table is only present when the user has expanded details, so this is genuinely best-effort.
 * Labels are normalised (`from:`, `From`, `reply-to:` → `from`, `reply-to`).
 */
function extractDetailRows(root: Element): Map<string, string> {
  const rows = new Map<string, string>();
  const table = queryFirst(root, SELECTORS.detailsTable);
  if (table === null) return rows;

  for (const tr of queryAll(table, ['tr'])) {
    const cells = queryAll(tr, ['td']);
    if (cells.length < 2) continue;
    const label = collapseWhitespace(cells[0]?.textContent ?? '')
      .toLowerCase()
      .replace(/:$/u, '')
      .trim();
    const value = collapseWhitespace(cells[1]?.textContent ?? '');
    if (label !== '' && value !== '' && !rows.has(label)) {
      rows.set(label, truncate(value, 400));
    }
  }
  return rows;
}

/**
 * The signed-in mailbox, read from Gmail's account chrome.
 *
 * Two independent sources, because this is now load-bearing twice over: it answers "is this sender
 * internal or external" for business email compromise detection, and it is how a message the user wrote
 * is recognised. Failing to read it degrades to assessing the user's own replies, so the document title
 * (`<folder> - <account> - Gmail`) backs up the account link's `aria-label`.
 *
 * Never sent anywhere.
 */
function readAccountAddress(): string | undefined {
  try {
    const label = queryFirst(document, SELECTORS.accountLink)?.getAttribute('aria-label') ?? '';
    const match = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/u.exec(label);
    if (match?.[0] !== undefined) return match[0].toLowerCase();
  } catch {
    // Fall through to the title.
  }

  try {
    return accountAddressFromTitle(document.title);
  } catch {
    return undefined;
  }
}

function extractSubject(): string {
  return truncate(collapseWhitespace(rawSubject()), 998);
}

/**
 * The subject with its whitespace intact.
 *
 * Deliberately not trimmed: trailing padding is the thing being preserved. Bounded at the RFC 5322
 * line limit, which is well above any legitimate subject and still leaves padding measurable.
 */
function rawSubject(): string {
  const element = queryFirst(document, SELECTORS.subject);
  return truncate(element?.textContent ?? '', 998);
}

// ---------------------------------------------------------------------------
// Body
// ---------------------------------------------------------------------------

/**
 * Visible body text with quoted history removed.
 *
 * The body element is cloned before the quoted blocks are stripped, so Gmail's live DOM is never
 * modified. This costs a shallow clone per analysis and is worth it: mutating Gmail's own nodes risks
 * breaking its event handlers, which the brief explicitly rules out.
 */
function extractBodyText(bodyElement: Element | null): string {
  if (bodyElement === null) return '';

  const clone = bodyElement.cloneNode(true) as Element;
  for (const quoted of queryAllUnion(clone, SELECTORS.quotedContent)) {
    quoted.remove();
  }
  for (const hidden of queryAll(clone, ['style', 'script', '[aria-hidden="true"]'])) {
    hidden.remove();
  }

  return truncate(normalizeBodyWhitespace(clone.textContent), MAX_BODY_CHARS);
}

/** Collapses runs of blank lines while keeping paragraph structure readable for the excerpts. */
function normalizeBodyWhitespace(text: string): string {
  return text
    .replace(/\r\n?/gu, '\n')
    .replace(/[ \t\u00a0]+/gu, ' ')
    .replace(/ ?\n ?/gu, '\n')
    .replace(/\n{3,}/gu, '\n\n')
    .trim();
}

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

function extractLinks(bodyElement: Element | null): EmailLink[] {
  if (bodyElement === null) return [];
  const links: EmailLink[] = [];
  const seen = new Set<string>();

  for (const anchor of queryAll(bodyElement, SELECTORS.bodyLink)) {
    if (links.length >= MAX_LINKS) break;

    // `getAttribute` rather than `.href`: the property resolves relative URLs against the current
    // document, which would silently turn a broken href into a plausible mail.google.com URL.
    const href = anchor.getAttribute('href')?.trim() ?? '';
    if (href === '' || href.startsWith('#')) continue;

    const text = collapseWhitespace(anchor.textContent);
    const key = `${text}\u0000${href}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const parsed = parseUrl(href);
    links.push({
      text: truncate(text, 512),
      href: truncate(href, 4096),
      normalizedDomain: parsed === null ? '' : normalizeDomain(parsed.hostname),
    });
  }
  return links;
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

/**
 * Attachment metadata from the chips Gmail renders in the message footer.
 *
 * Filenames only. Nothing is downloaded, opened, hashed, or requested — not even a HEAD. Gmail's
 * `download_url` attribute (`<mime>:<filename>:<url>`) is read for the filename and never fetched.
 */
function extractAttachments(root: Element): EmailAttachment[] {
  const attachments: EmailAttachment[] = [];
  const seen = new Set<string>();

  for (const chip of queryAllUnion(root, SELECTORS.attachmentChip)) {
    if (attachments.length >= MAX_ATTACHMENTS) break;

    const filename = collapseWhitespace(
      chip.getAttribute('download_url')?.split(':')[1] ?? chip.textContent,
    );
    if (filename === '' || seen.has(filename)) continue;
    seen.add(filename);

    attachments.push({ filename: truncate(filename, 400), extension: fileExtension(filename) });
  }
  return attachments;
}

// ---------------------------------------------------------------------------
// Authentication surfaces
// ---------------------------------------------------------------------------

const VERDICT_WORDS: readonly [RegExp, AuthVerdict][] = [
  [/\bpass(ed)?\b/iu, 'pass'],
  [/\bsoft ?fail\b/iu, 'softfail'],
  [/\bfail(ed|s)?\b/iu, 'fail'],
  [/\bneutral\b/iu, 'neutral'],
  [/\bnone\b/iu, 'none'],
];

function readVerdict(text: string): AuthVerdict | undefined {
  for (const [pattern, verdict] of VERDICT_WORDS) {
    if (pattern.test(text)) return verdict;
  }
  return undefined;
}

/**
 * Best-effort authentication state from Gmail's own UI.
 *
 * A content script cannot read `Authentication-Results` headers, so this reads the details table
 * ("mailed-by", "signed-by"), the `via` annotation, Gmail's warning banner, and the
 * unauthenticated-sender avatar. All are frequently absent, which is why the `authentication`
 * detectors are written to stay silent rather than guess. See `rules/authentication.ts`.
 */
function extractAuth(root: Element): EmailAuthInfo | undefined {
  const info: EmailAuthInfo = {};
  const rows = extractDetailRows(root);

  const mailedBy = rows.get('mailed-by');
  if (mailedBy !== undefined) info.mailedBy = normalizeDomain(stripToDomain(mailedBy));

  const signedBy = rows.get('signed-by');
  if (signedBy !== undefined) info.signedBy = normalizeDomain(stripToDomain(signedBy));

  const security = rows.get('security');
  if (security !== undefined) {
    const verdict = readVerdict(security);
    if (verdict !== undefined) info.spf = verdict;
  }

  // Some Gmail builds put the whole authentication summary into a tooltip.
  const tooltip = queryFirst(root, SELECTORS.detailsToggle)?.getAttribute('data-tooltip') ?? '';
  for (const [key, mechanism] of [
    ['spf', 'spf'],
    ['dkim', 'dkim'],
    ['dmarc', 'dmarc'],
  ] as const) {
    const match = new RegExp(`${mechanism}\\s*[:=]?\\s*(\\w+)`, 'iu').exec(tooltip);
    const verdict = match?.[1] === undefined ? undefined : readVerdict(match[1]);
    if (verdict !== undefined) info[key] = verdict;
  }

  const via = readVia(root);
  if (via !== undefined) info.via = via;

  const banner = queryFirst(root, SELECTORS.warningBanner)?.textContent ?? '';
  const warningText = readGmailWarning(collapseWhitespace(banner));
  if (warningText !== undefined) info.gmailWarning = warningText;

  if (queryFirst(root, SELECTORS.unauthenticatedIndicator) !== null) {
    info.unauthenticatedIndicator = true;
  }

  return Object.keys(info).length > 0 ? info : undefined;
}

/**
 * Gmail's banner text, but only when it is a **verdict about the message** rather than an explanation
 * of where the message is filed.
 *
 * Gmail's alert region serves two different purposes that read almost identically:
 *
 *  - *A verdict.* "Be careful with this message. It contains content that's typically used to steal
 *    personal information." Gmail applies reputation data and account history we have no access to, so
 *    this is genuine corroboration.
 *  - *A placement notice.* "Why is this message in spam? It's similar to messages that were detected by
 *    our spam filters." Every message in the spam folder carries one, including messages the user filed
 *    there by hand.
 *
 * Treating the second as the first made the score depend on which folder was open — the same message
 * scored differently in Spam than in the Inbox — and let a manual "mark as spam" come back as a security
 * finding. So a banner framed as placement is discarded **in full**, including any security wording
 * inside it, because in that frame the wording is Gmail's filing rationale rather than a warning to the
 * reader.
 */
export function readGmailWarning(bannerText: string): string | undefined {
  if (bannerText === '') return undefined;
  if (PLACEMENT_NOTICE.test(bannerText)) return undefined;
  if (!SECURITY_VERDICT.test(bannerText)) return undefined;
  return truncate(bannerText, 300);
}

/** Gmail explaining where a message is filed, or reflecting an action the user took. */
const PLACEMENT_NOTICE =
  /(why is this message in spam|why am i seeing this|it'?s in spam|this message is in (spam|trash|the bin)|you marked (it|this|this message)|marked (it|this message) as spam|reported (it|this message) as|similar to messages that (were|have been) detected|moved to (spam|trash|the bin)|\bnot spam\b|deleted messages are|messages that have been in \w+ more than)/iu;

/** Wording that makes a banner a statement about the message's safety. */
const SECURITY_VERDICT =
  /\b(be careful|seems dangerous|dangerous|suspicious|spoof|phishing|not verify|could not verify|impersonat|caution|fraud)\b/iu;

function readVia(root: Element): string | undefined {
  const header = collapseWhitespace(queryFirst(root, SELECTORS.senderTextual)?.textContent ?? '');
  const match = /\bvia\s+([\w.-]+\.[a-z]{2,})/iu.exec(header);
  if (match?.[1] !== undefined) return normalizeDomain(match[1]);

  const row = extractDetailRows(root).get('via');
  return row === undefined ? undefined : normalizeDomain(stripToDomain(row));
}

/** `"example.com"` / `"user@example.com"` / `"example.com (verified)"` → `example.com`. */
function stripToDomain(value: string): string {
  const trimmed = value.trim().split(/\s+/u)[0] ?? '';
  const fromAddress = emailDomain(trimmed);
  return fromAddress !== '' ? fromAddress : trimmed.replace(/^@/u, '');
}

// ---------------------------------------------------------------------------
// Ids and layout anchors
// ---------------------------------------------------------------------------

function readMessageId(element: Element): string {
  return (
    element.getAttribute('data-message-id') ??
    element.getAttribute('data-legacy-message-id') ??
    element.getAttribute('id') ??
    ''
  );
}

function readThreadId(): string {
  const subject = queryFirst(document, SELECTORS.subject);
  return (
    subject?.getAttribute('data-thread-perm-id') ??
    subject?.getAttribute('data-legacy-thread-id') ??
    ''
  );
}

/**
 * True when a message row is expanded (i.e. its body is on screen). Gmail marks collapsed rows with
 * classes like `.kv`/`.kQ`, so the absence of those plus the presence of a body is the test.
 */
function isExpanded(element: Element): boolean {
  for (const selector of SELECTORS.collapsedMessage) {
    try {
      if (element.matches(selector)) return false;
      // A collapsed row contains the collapsed marker as a direct descendant of its header.
      if (element.querySelector(`:scope > ${selector}`) !== null) return false;
    } catch {
      // Ignore unsupported selectors (`:scope` is broadly supported but be defensive).
    }
  }
  return queryFirst(element, SELECTORS.body) !== null;
}

/**
 * Where the badge gets attached.
 *
 * Preference order is deliberate. The right-hand cluster of the header row is tried first, because
 * that places the badge on the sender's line, in the space beside the timestamp. The header container
 * is only a fallback: a badge appended there becomes the container's last block and renders on a line
 * of its own underneath the recipient row, which is where it used to sit.
 *
 * Every candidate is a placement, not a requirement — if Gmail's markup has moved on, a worse
 * position is an acceptable outcome and no position is not.
 */
function findHeaderAnchorPoint(element: Element): Element | null {
  const inline = queryFirst(element, SELECTORS.headerRightCluster);
  if (inline !== null) return inline;

  for (const selector of ['.gE.iv.gt', '.gE', '.iw', '.gK', '.go', '.hb']) {
    const found = element.querySelector(selector);
    if (found !== null) return found;
  }
  return element.firstElementChild;
}

export const __testables = {
  normalizeBodyWhitespace,
  stripToDomain,
  readVerdict,
  readGmailWarning,
  isOutboundMessage,
  selectReadableMessage,
  isOutboundLabel,
  accountAddressFromTitle,
};
