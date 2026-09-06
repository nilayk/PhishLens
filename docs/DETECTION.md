# Detection and scoring

How a message becomes a number, and why the number is shaped the way it is. For the reasoning behind
individual design decisions, see [ARCHITECTURE.md](ARCHITECTURE.md); this document describes what the
system does.

## The design principle

> Use deterministic security signals for the things a computer can know, and use a language model only
> for the things that require semantic judgement.

Whether `rnicrosoft-online.com` is Microsoft-owned is a fact — code decides it, and it is right every
time. Whether "please confirm the wire details before Friday" is a business email compromise attempt is a
reading — a model can help, and it is sometimes wrong. Mixing the two produces a number nobody can argue
with. PhishLens keeps them apart the whole way through: separate detectors, a separate scoring category,
a separate section of the card, and different wording in each.

## What is checked

Five deterministic categories, each a directory of detectors under `src/analysis/rules/`.

**Identity** (`identity.ts`) — impersonation of an organisation. Lookalike domains within a bounded edit
distance of a real one, homoglyph and mixed-script spellings, punycode, brand names placed in a subdomain
or local part rather than the registrable domain, and display names claiming an organisation the sending
domain has nothing to do with. The last of these needs no brand table, which is what keeps the category
working for the insurer or council that no curated list contains.

**Links** (`links.ts`) — anchor text that names one destination while the href goes to another, the
registrable domain buried behind a convincing prefix (`login.microsoftonline.com.session-verify.net`),
raw and obfuscated IP addresses, punycode hosts, shorteners, redirect chains and redirect parameters
carrying a second URL, credential-related wording pointing at an unrelated domain, and non-web schemes.

**Attachments** (`attachments.ts`) — executable and script types, macro-enabled documents, archives,
double extensions, and right-to-left override characters used to make `invoice⁧fdp.exe` read as a PDF.

**Content** (`content.ts`) — requests to sign in or confirm credentials, payment and bank-detail changes,
gift cards, manufactured urgency and consequence, and the structural tells of a lure (a body that is
nothing but a link, a subject padded to hide its real text).

**Authentication** (`authentication.ts`) — SPF, DKIM and DMARC results, and Gmail's own warning banner,
as far as Gmail exposes them in the page. There is no access to raw headers.

Every detector emits `SecuritySignal`s carrying an id, a category, a severity, a human explanation, and
where applicable the evidence and a locator the UI can highlight. A detector never computes a score.

## The score

A 0–100 integer assembled from capped per-category subtotals. **Every number lives in
`src/analysis/scoring/config.ts` and nowhere else**, so the model's behaviour can be read off one file.

| Category | Weight |
| --- | --- |
| Links | 25 |
| Identity (impersonation, lookalikes, homoglyphs) | 21 |
| Content / social engineering | 15 |
| Semantic (the AI model) | 15 |
| Authentication (SPF/DKIM/DMARC as exposed by Gmail) | 14 |
| Attachments | 10 |

Aggregation is pure functions in `src/analysis/scoring/aggregate.ts`, tested in isolation from the
detectors:

1. Each signal's score is capped at a per-severity ceiling — `info` 5, `low` 15, `medium` 35, `high` 65,
   `critical` 100.
2. Signals within a category are summed, and the subtotal is capped at the category's weight.
3. The total is the sum of subtotals, clamped to `[0, 100]`.
4. A single **deterministic** finding of `high` or `critical` severity establishes a score *floor* of 50
   or 75 respectively.

The weights sum to exactly 100. If they summed to more, the final clamp would fire on ordinary
suspicious mail and compress the top of the scale until 80 and 100 meant the same thing.

### Why there is a floor

Step 4 is the one departure from a purely additive model, and it exists because additive scoring has a
structural blind spot: an attack that is malicious in only one dimension can never exceed that
dimension's weight. A gift-card or payroll-diversion email is plain text from a real mailbox with no
links, no attachments and passing authentication. It is *entirely* a content finding, so it would top out
at 15/100 and be reported as low risk. The floor stops a single-dimension attack from being diluted by
the categories it happens not to touch.

The floor is restricted to deterministic signals, so the AI cannot trigger one. It also excludes
`authentication.gmail_warning` by id: Gmail shows that banner conditionally on the folder being viewed,
so letting it set the verdict would make a message's score change when you moved it to Spam.

When a floor is what produced the score, the card labels it, because a breakdown whose categories add up
to less than the total looks like broken arithmetic otherwise.

## Holding down false positives

A security indicator that cries wolf gets ignored, at which point it is worse than nothing. Several
mechanisms exist purely to keep legitimate mail at zero.

- **Dampening.** Content findings are softened when the sender is authenticated, on a brand-owned domain,
  and not impersonating anyone — a real password-reset email says all the same alarming things a fake one
  does. The signals are still reported; they carry a `dampened` flag and are excluded from corroborating
  the AI verdict, so a softened finding cannot be used to license a score elsewhere.
- **Bulk-mail shape.** Newsletters have many links across many domains and would otherwise trip
  link-heavy heuristics. Recognising the shape suppresses the heuristics that assume person-to-person
  mail.
- **Sender-domain redirects.** Newsletter platforms rewrite every link through their own redirector while
  the anchor text names the real destination, which is exactly the pattern the strongest link rule looks
  for. Links whose host is on the *sender's own registrable domain* are exempt from the mismatch and
  redirect rules, which covers every such platform without needing a list of them.
- **Word-boundary brand matching.** Short brand keywords (`irs`, `aws`) must match as whole folded words,
  or "first" and "lawsuit" become brand claims once separators are stripped for comparison.
- **The AI dead zone.** Verdicts below 45/100, and any verdict no deterministic check corroborates, score
  zero. See [LOCAL-AI.md](LOCAL-AI.md).

The fixture suite enforces this: legitimate fixtures must score low **and** produce no `high` or
`critical` deterministic signal, which is what makes the severity floors safe rather than merely
plausible.

## Confidence in the numbers

610 tests run the real pipeline in plain Node — no Chrome, no Gmail, no network. The corpus in
`test/fixtures/` holds 16 messages: a plain legitimate message, a legitimate password reset, a newsletter
with many links, a newsletter whose links are all rewritten through its platform's click tracker, an
invoice, PayPal phishing, a Microsoft lookalike domain, a brand spoof from an unlisted lead-generation
sender, an anchor-URL mismatch, a punycode link, an IP-address URL, a ZIP attachment, an executable
attachment, a gift-card scam, a fake payroll change, and an MFA-code request.

Fixtures store what a human would write down — anchor text, href, filename — and the loader derives
`normalizedDomain` and `extension` using the same helpers the Gmail adapter uses. If fixtures hard-coded
those, a bug in normalisation would be invisible, because the fixture would carry the correct answer that
production code failed to compute.

See [DEVELOPMENT.md](DEVELOPMENT.md) for what each test file covers and how to run them.

## Limitations of the approach

- **The brand list is curated, not exhaustive** (`src/shared/brands.ts`). Impersonation of an unlisted
  brand is caught by the brand-independent signals, which ask whether the display name shares any name
  with the sending domain, but the precise findings — lookalike distance, "not a Microsoft-owned domain" —
  only apply to listed brands.
- **The public suffix list is a pragmatic subset** (`src/shared/public-suffix.ts`), not the full PSL. It
  covers common multi-label suffixes; an unusual one may be misparsed at the registrable boundary.
- **English-centric content heuristics.** Social-engineering patterns are English. Non-English phishing is
  caught by identity, link and attachment signals but not content ones.
- **Authentication is second-hand.** No raw headers means no Received chain analysis and reliance on
  Gmail's summary where it is rendered at all.
- **The body is truncated** — 200,000 characters for analysis, 4,000 for the model. A lure buried past the
  cut in a very long message can be missed.
- **No reputation or intelligence feeds**, by design. A phishing page on a freshly registered but
  otherwise unremarkable domain scores on its structure alone.
- **Highlighting is coarse for text.** To avoid restructuring Gmail's DOM, the smallest existing element
  containing the evidence is outlined rather than the exact character range.
