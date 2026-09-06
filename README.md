# PhishLens

An explainable phishing, malware and social-engineering risk indicator for Gmail, as a Chrome
Manifest V3 extension.

When you open a message you received, PhishLens analyses it locally and shows a compact badge on the
right of the message header, level with the sender's address:

```text
✓ Low Risk · 8/100          ⚠ Suspicious · 58/100          ⛔ High Risk · 91/100
```

Clicking the badge opens a card in the bottom-right corner that says *why*, separating what was
measured from what was guessed. It stays put while you scroll and read, and leaves Gmail fully usable
while it is open:

```text
Observed
  HIGH      Sender domain resembles Microsoft but is not Microsoft-owned
            rnicrosoft-online.com is not a domain Microsoft operates.
  HIGH      Displayed link address differs from its actual destination
            shown: login.microsoftonline.com → actual: session-verify-portal.net
  MEDIUM    Message requests immediate credential verification
  INFO      No attachments were present

AI assessment
  This is a language assessment by the on-device model, not a verified technical finding.
```

It is **advisory only**. It does not block links, downloads, replies, or anything else Gmail does.

## Design principle

> Use deterministic security signals for the things a computer can know, and use a language model only
> for the things that require semantic judgement.

Whether `rnicrosoft-online.com` is Microsoft-owned is a fact — code decides that, and it is right every
time. Whether "please confirm the wire details before Friday" is a business email compromise attempt is
a reading — a model can help, and it is sometimes wrong. Mixing the two produces a number nobody can
argue with. PhishLens keeps them apart all the way through: separate detectors, separate scoring
category, separate section of the UI, separate wording.

The practical consequence is that the model is *capped*. The `llm` category is worth 15 of the 100
points and is additive only, so a model that has been successfully prompt-injected into declaring a
phishing email safe changes the score by at most 15 points downward from where it would otherwise be —
it cannot remove a single deterministic finding. This is enforced arithmetically and covered by tests
(`test/semantic.test.ts`), not by convention.

It is also *calibrated*, which turned out to matter as much as the cap. Measured against the real
on-device model, Gemini Nano is accurate on genuine fraud and markedly over-suspicious on legitimate
mail — it will rate an ordinary product announcement 95/100 and cite "Suspicious Sender Email" as its
reason, a judgement it has no way to make. So the prompt tells it not to reason about domains, links
or addresses at all, and the scoring ignores any verdict below 45/100 as well as any verdict that no
deterministic check corroborates. The verdict is still displayed with the model's reasoning; it simply
does not move the number. See [§4.3.1](docs/ARCHITECTURE.md) for why suppressing the score entirely
costs no detection capability.

## Architecture

Full design notes, including the decisions and their justifications, are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). The short version:

```text
src/
  content/      orchestration: observe → extract → analyse → render (all state lives here)
  background/   service worker: settings, future cloud egress. Deliberately stateless.
  gmail/        DOM adapter + SPA observer. The only place that knows Gmail's markup.
  analysis/
    rules/      deterministic detectors: identity, link, attachment, content, authentication
    scoring/    weights, ceilings, thresholds, and the pure aggregation function
    llm/        semantic layer: prompt, strict output parsing, on-device + cloud adapters
  ui/           badge, panel, highlighting. No framework; Shadow DOM; textContent only.
  shared/       types, URL/Unicode/brand primitives, settings, logging
```

Data flows one way: `gmail/` produces an `EmailMessage`, `analysis/` turns that into an
`AnalysisResult`, `ui/` renders it. `analysis/` imports nothing from `gmail/` or `ui/` and touches no
browser API, which is why the whole detection engine runs under `vitest` in plain Node.

### Toolchain

| Choice | Why |
| --- | --- |
| TypeScript ES2022, `strict` | Plus `noUncheckedIndexedAccess` and `noPropertyAccessFromIndexSignature`, because most of this code indexes into structures derived from hostile input. |
| **esbuild**, not Vite | Three entry points with three different output contracts (the content script must be an IIFE — MV3 declared content scripts are classic scripts — while the worker and options page are ESM). A dev server, Vite's main advantage, is worth little here because the primary UI only exists injected into Gmail's DOM, so it has to be verified in Gmail regardless. esbuild also keeps the dependency tree small, which matters for a security tool that asks to read your mail. Full build is ~50 ms. |
| Vitest | ESM-native, no transform config, and fast enough that the fixture suite is usable as an inner-loop tool. |
| ESLint + `typescript-eslint` (`strictTypeChecked`) | Flags `any`, unused vars, and floating promises as required, plus `no-innerHTML`/`no-eval` house rules that make the XSS-safety posture mechanical rather than aspirational. |
| Zero runtime dependencies | `"dependencies": {}`. Everything shipped into the browser is in `src/`, and can be read end to end. |

### Scoring

A 0–100 score assembled from capped, per-category subtotals. All numbers live in
`src/analysis/scoring/config.ts` and nowhere else.

| Category | Weight |
| --- | --- |
| Identity (impersonation, lookalikes, homoglyphs) | 21 |
| Links | 25 |
| Content / social engineering | 15 |
| Authentication (SPF/DKIM/DMARC as exposed by Gmail) | 14 |
| Attachments | 10 |
| Semantic (LLM) | 15 |

Aggregation, implemented as pure functions in `src/analysis/scoring/aggregate.ts` and tested in
isolation:

1. Each signal's score is capped at a per-severity ceiling (`info` 5, `low` 15, `medium` 35, `high` 65,
   `critical` 100).
2. Signals within a category are summed, then the subtotal is capped at the category's weight.
3. The total is the sum of subtotals, clamped to `[0, 100]`.
4. A single *deterministic* finding of `high` or `critical` severity additionally establishes a score
   **floor** (50 and 75).

Step 4 deviates from a pure additive model, deliberately. Purely additive scoring has a structural
blind spot: an attack that is malicious in only one dimension can never exceed that dimension's weight.
A gift-card or payroll-diversion email is a plain-text message from a real mailbox with no links, no
attachments and passing authentication — it is *entirely* a content finding, so it would top out at
15/100 and be reported as low risk. The floor stops a single-dimension attack from being diluted by the
categories it happens not to touch. It is restricted to deterministic signals, so the model cannot
trigger one.

Weights deviate from the brief's suggested table in one documented way: the table had no row for
content signals and split identity across two overlapping rows ("Authentication / identity 30" +
"Sender/domain 15" = 45). Here that 45 becomes identity 21 + authentication 14, content gets the 15 it
needs, and the LLM's 20 becomes 15 so the weights sum to exactly 100. Summing to exactly 100 matters:
if they summed to more, the final clamp would fire on ordinary suspicious mail and compress the top of
the scale until 80 and 100 meant the same thing.

## Installation

Requires **Node.js ≥ 20.11.0** (also declared in `package.json` `engines`) and **Chrome ≥ 120**.

```bash
npm install
npm run build
```

Then, in Chrome:

1. Go to `chrome://extensions`.
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select the `dist/` directory.
4. Open Gmail and open any message. The badge appears at the right of the message header, beside the
   timestamp. Click it for the explanation card.

Settings are on the extension's options page (`chrome://extensions` → PhishLens → Details → Extension
options).

## Development

```bash
npm run dev          # esbuild watch; reload the extension in Chrome to pick up changes
npm run build        # production build to dist/
npm run build:dev    # unminified build with inline sourcemaps and debug logging enabled
npm run clean        # remove dist/

npm run typecheck    # tsc --noEmit
npm run lint         # eslint .
npm run lint:fix
npm test             # vitest run
npm run test:watch
npm run test:coverage

npm run verify       # lint && typecheck && test — run this before committing
```

The icons in `dist/icons/` are generated at build time by `scripts/gen-icons.mjs` rather than committed
as binaries, so that no opaque blob ships in a repository whose whole value is being auditable.

### Testing

596 tests, all in plain Node — no Chrome, no Gmail, no network.

| File | Covers |
| --- | --- |
| `test/aggregate.test.ts` | The scoring functions in isolation: per-severity ceilings, category caps, `[0, 100]` clamping, and zero contribution from an empty category (which is the "local model unavailable" path). |
| `test/detection.test.ts` | The full pipeline against 16 fixtures, plus invariants across all of them, plus which message in a thread gets picked — including the forged-from-yourself cases that must *not* be skipped. |
| `test/semantic.test.ts` | The LLM containment guarantees, the calibration limits, and the unavailable/throwing/hanging/cancelled analyzer paths — including which status each one reports and which of them may be cached. |
| `test/chrome-prompt.test.ts` | The on-device adapter against fakes for every API shape Chrome has shipped, and every malformed shape it might, plus concurrency: a session fake that rejects overlapping prompts the way the real one does. |
| `test/url.test.ts` | Obfuscated IP forms, forged suffix boundaries, redirect chains, hostnames `new URL()` accepts but that cannot exist. |
| `test/unicode.test.ts` | Punycode decoding, script mixing, bidi tricks, confusable folding, bounded edit distance. |
| `test/privacy.test.ts` | Settings validation, and what `buildCloudPayload` **drops** as well as what it keeps. |

Fixtures in `test/fixtures/` cover a legitimate message, a legitimate password reset, a legitimate
newsletter with many links, a legitimate newsletter whose links are all rewritten through the sending
platform's click tracker, a legitimate invoice, PayPal phishing, a Microsoft lookalike domain, an
anchor-URL mismatch, a punycode link, an IP-address URL, a ZIP attachment, an executable attachment, an
executive gift-card scam, a fake payroll change, and an MFA-code request.

Fixtures store what a human would write down — anchor text, href, filename — and the loader derives
`normalizedDomain` and `extension` using the same helpers the Gmail adapter uses. If fixtures hard-coded
those, a bug in normalisation would be invisible, because the fixture would carry the correct answer
that production code failed to compute.

The suite asserts in both directions. Phishing fixtures must score high, and legitimate fixtures must
score low *and* produce no `high` or `critical` deterministic signal — which is what makes the severity
floors safe rather than merely plausible.

## Permissions

Mapped 1:1 to `src/manifest.json`. There are two.

| Manifest entry | Why it is needed |
| --- | --- |
| `"host_permissions": ["https://mail.google.com/*"]` | The content script reads the open message from the page to analyse it. This is the only origin PhishLens can run on. |
| `"permissions": ["storage"]` | Persists the four settings on the options page (AI mode, backend URL, and two display toggles). No message content is ever written to storage. |

Not requested, and not needed: `activeTab`, `<all_urls>`, `tabs`, `scripting`, `webRequest`,
`declarativeNetRequest`, `downloads`, `cookies`, `identity`, `nativeMessaging`. The content script is
declared in the manifest, so `scripting` is unnecessary. Nothing is fetched, blocked, or rewritten, so
the network permissions are unnecessary.

The extension pages run under `script-src 'self'; object-src 'none'; base-uri 'none'`.

If a future feature seems to need something broader, that is a signal to reconsider the feature.

## Privacy model

The three categories of data are kept explicitly separate.

**Extracted from Gmail** — sender name and address, Reply-To, subject, visible body text (truncated,
quoted replies removed), link anchor text and hrefs, attachment filenames and extensions, and Gmail's
own authentication summary when it is exposed in the DOM. This lives in memory in the content script
for as long as the message is on screen and is then dropped. It is never written to `chrome.storage`,
never sent to the service worker, and never logged in a release build.

**Analysed locally** — all of it. Every deterministic detector, the whole scoring engine, and (in the
default configuration) the semantic layer run inside the tab. Nothing touches the network. Analysis
results are cached in the tab, capped at 20 entries, and discarded when the tab closes.

**Potentially leaving the browser** — nothing, unless you explicitly switch AI mode to
*Cloud-assisted* **and** enter a backend URL. Neither has a default value, so there is no configuration
of the shipped MVP in which data leaves the machine. If you do enable it, the single function that
builds the outbound payload is `src/analysis/llm/redact.ts` — one short file, deliberately, so that
"what would leave" is reviewable rather than an emergent property of whatever the adapter serialises.
It sends the subject, a body excerpt with email addresses reduced to their domains, the sender domain, a
*description* of the display name's shape (`three-words-role-account`, not the name), link registrable
domains, attachment extensions, and the ids of findings already made. It drops the recipient address,
the sender's local part, message and thread ids, full URLs, and filenames.

Other choices that follow from this:

- **No logging of message content.** `src/shared/logger.ts` compiles to a no-op in release builds via a
  build-time flag, and even in dev builds it redacts.
- **No API keys in the extension.** An API key shipped in an extension is a public API key. If cloud
  analysis is ever built, the extension talks only to our own backend and the backend holds the vendor
  credential. The `fetch` in the service worker sends `credentials: 'omit'` and `redirect: 'error'`, so
  it cannot follow a redirect to another origin or attach ambient cookies.
- **Nothing in an email is ever fetched.** No URL is requested, no attachment is downloaded, no
  preview is generated, no DNS lookup is made. All link and attachment analysis is textual.

## Local LLM behaviour

The semantic layer sits behind one interface:

```ts
interface SemanticAnalyzer {
  isAvailable(): Promise<boolean>;
  analyze(email: EmailMessage, options?: { signal?: AbortSignal }): Promise<SemanticAnalysis | null>;
}
```

The on-device implementation (`src/analysis/llm/chrome-prompt.ts`) targets Chrome's built-in Prompt API.

**This API is unstable, and the code treats it as such.** Across Chrome versions the entry point has
been `window.ai.languageModel`, `chrome.aiOriginTrial.languageModel`, and the current bare
`LanguageModel` global; availability has been reported both as `capabilities().available`
(`'no'` / `'after-download'` / `'readily'`) and as `availability()` (`'unavailable'` / `'downloadable'`
/ `'downloading'` / `'available'`); and it is commonly gated behind a `chrome://flags` entry, hardware
requirements, or an origin trial that a typical user has not enabled.

One consequence of that instability is worth stating explicitly, because it cost a real bug: the
current entry point is a **class**, so `typeof LanguageModel === 'function'`. A structural probe that
checks `typeof === 'object'` before reading properties — the natural way to write a defensive probe —
rejects the live API on every browser that has it, fails closed, and reports "no on-device model" with
complete conviction. The fakes in `test/chrome-prompt.test.ts` are therefore function-typed with static
methods, mirroring the browser's shape rather than merely its interface; object-literal fakes passed
this suite while the adapter was broken everywhere.

**What was developed and tested against.** The adapter probes all three factory shapes and both
availability vocabularies, and each of them — plus each way they can be malformed — is covered by fakes
in `test/chrome-prompt.test.ts`, which is what the CI signal actually rests on. Development targeted the
Chrome 138+ `LanguageModel` global shape as the primary path, with Chrome ≥ 120 as the manifest's
minimum. To exercise a real on-device model rather than the fakes you will need a Chrome build where
Gemini Nano is available, which currently means enabling `chrome://flags/#prompt-api-for-gemini-nano`
and `chrome://flags/#optimization-guide-on-device-model`, and waiting for the model to download. Expect
this to drift; the version-detection code is written so that drift degrades to "unavailable" rather than
to a crash.

**When it is unavailable** — which is the common case — the extension works normally. `isAvailable()`
fails closed: any missing global, unexpected shape, or thrown error resolves to `false` and never
propagates. The pipeline produces a complete, correctly-classified result with the `llm` category
contributing exactly zero, and the panel's AI section says the model did not run rather than staying
silent (silence would let you assume the AI approved the message). This path is tested, not assumed.

A `downloadable` or `downloading` model is deliberately treated as **unavailable**. Opening an email
should not trigger a multi-hundred-megabyte download.

**"Unavailable" and "not finished yet" are reported separately.** On-device inference takes a few
seconds, during which the deterministic score is already on screen and complete. The card shows a small
progress indicator for that window and only says the model is unavailable when it actually is — an
earlier version showed the permanent "unavailable in this browser" message and then replaced it with a
verdict seconds later, which teaches you to disbelieve the message in the case where it is true. The
engine reports `meta.semanticStatus` (`ready` · `unavailable` · `no-output` · `error` · `cancelled` ·
`off`) so the distinction survives all the way to the UI.

**An interrupted assessment is retried, not remembered.** If you leave a message before the model
answers, that attempt is cancelled — and a cancellation is not an outcome. It used to be recorded as
"the model returned no usable assessment" and then cached, so returning to that message served the cache,
which short-circuits before the model is ever asked again; the card kept reporting no assessment until
Gmail was reloaded, which is what made a reload look like the fix. Results are now only cached once the
semantic stage has actually settled (`ready` or `off`), so a cancelled attempt, a one-off timeout, or a
message read while Chrome was still downloading the model are all re-assessed on the next visit.

Other rules the semantic layer follows:

- Deterministic settings are requested where supported (`temperature: 0`, `topK: 1`), and a JSON schema
  constraint is requested where supported, with an unconstrained retry where it is not.
- Output must be JSON matching the schema. Validation is all-or-nothing: a malformed response yields
  `null`, never a partially-salvaged object, because a model that returned a malformed object is a model
  whose values are not trustworthy either — and a hostile email may well be the reason it is malformed.
- One inference has a 20-second timeout, after which the session is discarded and rebuilt.
- **One prompt at a time.** A session rejects a second `prompt()` while the first is outstanding, and
  this adapter treats a rejected inference as a poisoned session — so two overlapping calls do not
  degrade to one winning, they both fail. That was a real bug: Gmail renders a thread in stages, the
  first message opened after a page load therefore reported two or three times, and the resulting
  collision meant *no assessment on the first email and a working one on every message after it*. Model
  work is now serialised through a queue, and superseded messages are cancelled via `AbortSignal` rather
  than left to delay the message you are actually reading.
- The session is built at startup (`warmUp()`) rather than on first use, so its several seconds are spent
  while you are still looking at your inbox. Warming never downloads a model.
- The session is cached in the **content script**, never the service worker (see below).

## MV3 service worker

MV3 terminates the background service worker after roughly 30 seconds of idle time. Rather than work
around that, `src/background/index.ts` is written to be **stateless**: no module-level cache, no model
session, no in-flight analysis. Every handler re-reads `chrome.storage` from scratch and every message
is self-contained, so the worker can be killed at any instant with no observable effect.

Everything stateful lives in the content script, whose context lives as long as the Gmail tab: the
on-device model session, the bounded result cache, and the badge and panel instances. The worker's only
jobs are reading and writing settings, seeding defaults on install, and being the single egress point if
cloud analysis is ever enabled. It does not import the analysis engine or the model adapter at all.

## Gmail integration

Gmail is a hash-routed SPA, and neither available signal is sufficient alone:

- **`hashchange`/`popstate` alone** fires while the *previous* thread is still rendered. Extracting then
  analyses the old message and attributes the result to the new one — a stale verdict, which in a
  security tool is worse than no verdict.
- **A `MutationObserver` alone** fires dozens of times per thread open (avatars, quoted text, the chat
  roster) and also fires when Gmail re-renders the *same* thread, producing redundant re-analysis and a
  flickering badge.

So `src/gmail/observer.ts` uses both, reconciled through one view signature:
`routeThreadId | domMessageId | fingerprint(sender, subject, bodyLength, linkCount)`. The debounced
observer recomputes it and emits nothing when it is unchanged, which kills redundant re-analysis. A
route change records the expected thread id and starts a bounded reconciliation poll that emits only
once the DOM agrees with the route, which kills staleness; if reconciliation times out, the badge is
torn down rather than left attached to the wrong message. The fingerprint includes body length because
Gmail renders headers before bodies, so "the body has now actually arrived" needs to count as a change.

All selector knowledge is confined to `src/gmail/selectors.ts` as prioritised candidate lists, behind
the `MailAdapter` interface. When Gmail changes its markup, that file is the only thing that needs to
change.

### Messages you sent are not assessed

Within a thread, the adapter picks the last expanded message **you did not write**. Taking simply the
last expanded message meant that once you replied to something, your own reply was the newest message
and the one Gmail leaves open, so PhishLens assessed your outgoing mail rather than the message you had
received. If every expanded message in a thread is your own, no badge is shown.

"You wrote it" deliberately means *from your address **and** addressed to somebody else*, not just from
your address. Mail forged to look as though it came from your own account is a phishing genre of its own
("I have access to your account…"), it lands in your inbox, and Gmail displays it as being from *me*
just like a real sent message. Skipping on the From address alone would have exempted the whole genre,
so a message from your address that is also addressed *back to you* is still assessed. Addresses are
read from the header only, never the body, so a message cannot invent a recipient to suppress its own
assessment. See [§3.1](docs/ARCHITECTURE.md) for the full table of cases and the one residual gap.

## Current limitations

- **Gmail web only**, in the top-level frame. Not Inbox-style clients, not the mobile apps, not
  Gmail-in-an-iframe.
- **Selector fragility.** Extraction depends on Gmail's DOM. When it changes, findings that depend on a
  broken selector are silently absent rather than wrong — but absent is still a miss.
- **Header access is limited to what Gmail renders.** There is no access to raw headers, so
  authentication analysis relies on Gmail's own summary when it is exposed, and Received chains are not
  available.
- **Only expanded messages can be assessed.** A collapsed message has no body in the DOM, and PhishLens
  will not expand it, so a thread whose only expanded message is your own reply shows no badge until you
  open one of the received messages. Relatedly, a forgery from your own address that is addressed to a
  third party and reached you by Bcc looks exactly like a message you sent, and is skipped.
- **The brand list is curated, not exhaustive** (`src/shared/brands.ts`). Impersonation of a brand not on
  the list is caught by the brand-independent signals instead — `identity.unsupported_org_claim` asks
  whether the display name shares any name with the sending domain, which needs no table — but the
  precise, high-confidence findings (lookalike domains, "not a Microsoft-owned domain") only apply to
  listed brands.
- **The public suffix list is a pragmatic subset** (`src/shared/public-suffix.ts`), not the full PSL. It
  covers the common multi-label suffixes; an unusual one may be misparsed at the registrable boundary.
- **English-centric content heuristics.** The social-engineering keyword patterns are English. Non-English
  phishing is caught by identity, link and attachment signals but not by content signals.
- **The body is truncated** (to 200,000 characters for analysis, 4,000 for the model). A lure buried past
  the cut in a very long message can be missed, and the model in particular only sees the opening.
- **No reputation or intelligence feeds**, by design. Everything is derived from the message itself, so
  a phishing page on a freshly-registered but otherwise unremarkable domain scores on its structure
  alone.
- **Highlighting is coarse for text.** To avoid restructuring Gmail's DOM, the smallest existing element
  containing the evidence is outlined rather than the exact character range.
- **Advisory only.** Nothing is blocked.

## Future cloud architecture

Designed, deliberately not built. The seam already exists: `CloudAnalyzer` implements the same
`SemanticAnalyzer` interface as the on-device adapter, so enabling it changes no analysis, scoring, or
UI code.

```text
extension (content script)
  → chrome.runtime.sendMessage           # the only sender
  → service worker                       # the only egress point
  → POST https://<your-backend>/api/analyze
      { subject, bodyExcerpt, senderDomain, senderNameShape,
        replyToDomain?, linkDomains[], attachmentExtensions[], deterministicSignalIds[] }
  ← { risk, categories[], reasons[], confidence }
      → parseSemanticAnalysis()          # strict validation, all-or-nothing
      → semanticToSignals()              # capped at the llm weight, additive only
```

The properties this shape is chosen for:

- **No vendor credential in the extension, ever.** The backend holds it. Anything else is publishing it.
- **One egress point.** Only the service worker makes network requests, so there is exactly one function
  to audit.
- **One redaction function.** `buildCloudPayload` decides what leaves, and its output is asserted
  field-by-field in `test/privacy.test.ts` — including assertions about what must *not* be present, so
  that a field added carelessly later fails the suite.
- **Deterministic findings are sent as ids, not re-derived.** The backend does not need the data required
  to recompute them.
- **HTTPS-only, validated.** `normalizeBackendUrl` accepts only an `https:` origin plus optional path
  prefix, so storage editing cannot point the adapter at `http://`, at a `javascript:` URL, or directly
  at a model vendor.
- **Opt-in twice.** Cloud mode requires both an explicit mode choice and a URL.
- **No fallback from local to cloud.** If the on-device model is missing, PhishLens does not quietly send
  your mail to a server instead.

## Threat model

**Malicious HTML and email content.** Every string from a message — URL, filename, display name, subject,
body — is hostile input. It is bounded on extraction, never `eval`'d, never used to build a URL that gets
requested, and never parsed as HTML. All rendering goes through `src/ui/dom.ts`, which sets `textContent`
and never `innerHTML`; `innerHTML`, `outerHTML` and `insertAdjacentHTML` are ESLint errors project-wide.
URL parsing uses the platform parser rather than regexes, and Unicode is handled explicitly (punycode
decoding, script-mixing detection, confusable folding, bidi stripping) so that a homoglyph domain cannot
pass as a brand's. Regexes over message text are bounded and anchored to avoid catastrophic
backtracking. `clamp()` fails closed on non-finite input, so a crafted value cannot manufacture a score.

**Gmail DOM changes.** Treated as certain, not hypothetical. Selector knowledge is isolated in one file
behind an interface; extraction is written so a missing field is absent rather than wrong; and the
observer tears the badge down rather than showing a stale verdict when it cannot confirm what is on
screen. A selector break degrades to "fewer findings", never to "wrong findings" or a broken Gmail.

**Prompt injection.** Assumed to succeed sometimes. Containment is defence in depth: message content is
wrapped in delimiters, forged delimiters are neutralised, the system prompt states that the contents are
data and that anything resembling an instruction is itself evidence of manipulation, and the task is
restated *after* the content because models weight the end of the context heavily. But the real control
is architectural — a fully successful injection can only zero the `llm` category's 15 points. It cannot
delete a deterministic finding, cannot lower the score below the deterministic floor, and cannot change
the classification of a message that failed a technical check.

**Compromised or malicious external URLs.** PhishLens never dereferences anything found in a message: no
`fetch`, no prefetch, no favicon, no DNS, no attachment download or inspection. Analysis is purely
textual, so a URL in an email cannot become a request that leaks the fact you opened the message, and a
malicious server never sees PhishLens at all.

**Extension permission abuse.** The attack surface is kept small enough to audit: two permissions, one
origin, zero runtime dependencies, no remote code (MV3 forbids it and the CSP enforces it), no
`eval`/`Function`. The service worker only accepts messages whose `sender.id` matches the extension's own
id, which Chrome sets and a web page cannot forge, so a compromised page cannot drive the worker. The
worker's only network capability is a POST to a URL you configured yourself.

**API-key exposure.** Structurally impossible in the MVP, because there is no key. The extension holds no
vendor credential and no code path adds an `Authorization` header. If cloud analysis is built, the key
lives on the backend; that boundary is the reason the cloud design routes through our own service rather
than calling a model vendor directly.

**Data exfiltration.** The default configuration makes no network requests at all. Cloud mode requires two
explicit user actions, and even then a single reviewable function decides what leaves, with the recipient
address, sender local part, filenames, full URLs and message ids removed. Message bodies are never
persisted and never logged in a release build. There is no telemetry, no analytics, no error reporting,
and no automatic update channel beyond Chrome's own.

**What PhishLens does not defend against.** It is a reading aid, not a control. It does not stop you
clicking a link, opening an attachment, or replying. It cannot detect a phishing message that is textually
indistinguishable from legitimate mail — a compromised real account of a real correspondent sending a
plausible request from the usual domain will score low, correctly, on the evidence available. It is one
layer, and the weakest assumption in it is that the user reads the panel.

## Licence

MIT.
