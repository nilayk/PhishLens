# PhishLens — Architecture & Design Notes

PhishLens is a Chrome MV3 extension that produces an **explainable** 0–100 phishing/security risk
score for the Gmail message the user is currently reading.

This is the design record: what was decided, and why the obvious alternative was rejected. It is the
document to read before changing anything structural, and the one place where reasoning is preserved
rather than summarised. For what the system does rather than why, see
[DETECTION.md](DETECTION.md), [LOCAL-AI.md](LOCAL-AI.md), [PRIVACY.md](PRIVACY.md) and
[DEVELOPMENT.md](DEVELOPMENT.md).

The guiding principle:

> Use deterministic security signals for things a computer can *know*, and use an LLM only for
> things that require semantic judgement.

Everything a rule can prove (a link whose anchor text disagrees with its `href`, a punycode
hostname, a Reply-To on a different registrable domain) is decided by code. The LLM is only asked
about intent and tone, and its output is capped so it can never dominate or reverse a deterministic
finding.

---

## 1. Toolchain decisions

### 1.1 Bundler: esbuild (not Vite)

**Decision: esbuild, driven by a ~120-line `scripts/build.mjs`.**

Reasoning:

- There are three independent entry points with three *different* output requirements:
  - `src/content/index.ts` → **IIFE** (MV3 declared content scripts are classic scripts; they
    cannot be ES modules without a loader shim).
  - `src/background/index.ts` → **ESM** (`"type": "module"` service worker).
  - `src/options/index.ts` → **ESM** (loaded from `options.html` with `type="module"`).
    Expressing "one target is IIFE, two are ESM, none are hashed, all emit to flat `dist/`" is a
    handful of lines in esbuild and a fight with Vite's Rollup/HTML pipeline.
- **Vite's headline advantage — the HMR dev server — does not apply here.** The primary UI (badge +
  detail panel) is *injected into Gmail's live DOM inside a shadow root*. It cannot be meaningfully
  previewed at `localhost:5173` because it has no meaning outside a Gmail message header. The only
  standalone HTML surface is the options page, which is a static form; iterating on it via
  `npm run dev` (esbuild watch) + extension reload is fast enough that a dev server is not worth the
  config surface.
- Minimal dependency footprint is an explicit product requirement for a *security* extension whose
  code should be easy to audit. esbuild is one dependency; Vite pulls in Rollup and a plugin
  ecosystem. Fewer transitive deps = smaller supply-chain surface for a tool that reads email.
- Rebuilds are ~20–40 ms, so the watch loop is effectively instant.

Vitest is used for tests even though Vite is not the bundler — Vitest is standalone and does not
require the app to be built by Vite.

### 1.2 Everything else

| Concern    | Choice                                                                     |
| ---------- | -------------------------------------------------------------------------- |
| Language   | TypeScript, `target: ES2022`, `strict: true`, `noUncheckedIndexedAccess`    |
| Tests      | Vitest (`environment: node`) — ESM-native, fixture-friendly, no browser     |
| Lint       | ESLint 9 flat config + `typescript-eslint` `strictTypeChecked`              |
| Framework  | **None.** See §5.                                                          |
| Runtime deps | **Zero.** All detection is standard library + `URL` + `Intl`.             |
| Node       | `>=22.13.0` (`engines` in `package.json`, and the CI floor)                 |

Lint rules explicitly enforced as requested: `@typescript-eslint/no-explicit-any` (error),
`@typescript-eslint/no-unused-vars` (error), `@typescript-eslint/no-floating-promises` (error).

**Hard constraint honoured:** nothing in `src/shared`, `src/analysis` imports `chrome.*` or touches
`document`. `vitest run` executes the whole detection + scoring stack in plain Node.

---

## 2. Where code runs, and why (MV3 statefulness)

This is called out explicitly because MV3 service workers are non-persistent and are killed after
~30 s idle.

**Decision: the entire analysis pipeline runs in the content script's execution context. The
background service worker holds no analysis state at all.**

```
┌─ Gmail page (https://mail.google.com) ────────────────────────────────────────┐
│                                                                              │
│  main world: Gmail's own DOM                                                 │
│      ▲ read-only extraction        ▲ one appended shadow host, one <style>    │
│      │                             │                                         │
│  ┌───┴─────────────────────────────┴──────────────────────────────────────┐  │
│  │ CONTENT SCRIPT (isolated world) — long-lived, dies with the tab        │  │
│  │                                                                        │  │
│  │  gmail/observer  →  gmail/dom-adapter  →  EmailMessage                 │  │
│  │                                              │                         │  │
│  │                                    analysis/engine (pure)              │  │
│  │                                    ├─ rules/*   (deterministic)        │  │
│  │                                    ├─ scoring/* (pure aggregation)     │  │
│  │                                    └─ llm/chrome-prompt  ◀── on-device │  │
│  │                                              │           model session │  │
│  │                                       AnalysisResult                   │  │
│  │                                              │                         │  │
│  │                                    ui/badge + ui/panel (shadow DOM)    │  │
│  └────────────────────────────────────────────┬───────────────────────────┘  │
└───────────────────────────────────────────────┼──────────────────────────────┘
                                                │ chrome.runtime.sendMessage
                                                │ (settings read/write only,
                                                │  + future cloud egress)
                                   ┌────────────▼──────────────┐
                                   │ SERVICE WORKER — STATELESS │
                                   │ no cache, no model, no     │
                                   │ session; reads storage on  │
                                   │ every message and exits    │
                                   └────────────┬───────────────┘
                                                │ (future, opt-in only)
                                       POST https://<our-backend>/api/analyze
```

### 2.1 Consequences of that decision

- **The on-device model session (`LanguageModel.create(...)`) lives in the content script**, cached
  in a module-level variable there. The content script's context survives as long as the Gmail tab
  does, so a session created for the first analysed message is reused for subsequent messages. This
  is option (1) of the three offered in the brief. It is the right one because model session
  creation is the expensive part (it can involve a multi-hundred-MB on-device model), and paying it
  per message in a worker that keeps dying would make the feature unusable.
- The session is **defensively re-created**: `chrome-prompt.ts` treats a session as disposable and
  recreates it if any call throws (`InvalidStateError` after a session is destroyed by the browser,
  quota exhaustion, etc.). So even the content-script cache is not *assumed* to be alive.
- The session is **warmed at startup and used by one caller at a time** — see §2.2.
- **The service worker does exactly three things**, all of which are safe to lose at any instant:
  1. `GET_SETTINGS` / `SET_SETTINGS` — read/write `chrome.storage.sync`, no in-memory cache.
  2. `CLOUD_ANALYZE` — the single future egress point (see §6). It is a pure request/response
     `fetch` with no session.
  3. `chrome.runtime.onInstalled` — seed default settings.
  Every handler re-reads storage from scratch. There is no `let cache = ...` anywhere in
  `src/background/`, and this is asserted by a unit test over the module's source shape.
- **No use of `chrome.storage.session`** for analysis state. Analysis results are deliberately *not*
  persisted anywhere (see §7 — privacy). Re-analysis of a re-opened thread is cheap (single-digit
  ms for the rule engine), so there is nothing worth caching to disk. The only in-memory cache is a
  small per-tab `Map<viewSignature, AnalysisResult>` in the content script, bounded to 20 entries
  and destroyed on tab close.

### 2.2 One session, one prompt at a time

A Prompt API session processes a single prompt at a time; a second `prompt()` while the first is
outstanding is rejected. Combined with this adapter's policy of treating a rejected inference as a
poisoned session and destroying it, two overlapping calls do not degrade to one succeeding — **both
fail**, because the survivor's session is torn down underneath it.

Overlap is not an edge case here, it is what the observer produces by design. The view signature includes
body length (§3) precisely so that a header rendered before its body is not analysed as an empty message,
and Gmail fills a thread in stages, so the first message opened after a page load legitimately reports
two or three times as it arrives. Unserialised, the symptom is *no AI assessment on the first email and a
working one on every message after it* — later messages arrive in a single render and never overlap.

Three mechanisms, each addressing a different part of it:

- **Serialisation.** Every use of the session goes through a queue (`#enqueue`), whose tail is a promise
  that cannot reject, so one failed inference does not break the chain behind it.
- **Cancellation.** `SemanticAnalyzer.analyze` takes an `AbortSignal`, and the controller aborts the
  previous message's inference when the view changes. Serialisation alone would have made a stale
  analysis *delay* the current one instead of corrupting it — the queue must be able to drop work, not
  only order it. The signal is both checked locally and passed to the API, which can stop work already
  in progress. It needs explicit handling in the retry loop, because that loop's `catch` exists to
  swallow "this Chrome version rejected that option shape" and try the next, and an abort arrives as a
  rejection too.
- **Warm-up.** `warmUp()` builds the session at content-script startup, so the seconds it costs are
  spent while the user is still in their inbox. It never downloads: `isAvailable()` is false unless the
  model is already on disk, so a browser without one warms nothing.

#### 2.2.1 A cancelled attempt is not an answer

Cancellation introduces a distinction the pipeline has to preserve: *a conclusion* versus *a moment*. An
abort resolves the analyzer to `null`, which is indistinguishable from the model declining to answer
unless something records why. Two rules keep them apart:

- `cancelled` is its own `SemanticStatus`, set whenever the signal is aborted, whether the adapter
  reported it by resolving to nothing or by rejecting.
- `isSemanticSettled()` gates what may be cached: only `ready` (the model answered) and `off` (it was
  deliberately not asked). `cancelled`, `error`, `no-output` and `unavailable` are not kept.

The second rule matters because the cache short-circuits before the semantic stage runs, so a cached
non-answer can never be retried and would stand for the life of the tab. With it, a one-off timeout does
not mark a message permanently unassessable, and a message read while Chrome was still downloading the
model is re-assessed once the model is there. The cost is a re-run of the rule engine (single-digit
milliseconds) and one more inference attempt per visit.

---

## 3. Gmail integration: two signals, cross-checked

Gmail is a hash-routed SPA. Relying on either signal alone is broken:

- **`hashchange`/`popstate` alone** fires *before* Gmail has swapped in the new thread's DOM, so
  extraction at that moment yields the previous thread → **stale analysis**.
- **`MutationObserver` alone** misses nothing structurally, but fires dozens of times per thread
  open (avatars, quoted-text collapse, ads, chat roster), and also fires when Gmail re-renders the
  *same* thread → **redundant re-analysis** and badge flicker.

`src/gmail/observer.ts` combines them around a single concept, the **view signature**:

```ts
domSignature  = `${domMessageId}|${domThreadId}|${sender}|${cheapFingerprint(subject, bodyLen, linkCount)}`
viewSignature = `${routeThreadIdFromHash}|${domSignature}`
```

- A debounced (200 ms) `MutationObserver` on the conversation container recomputes the signature.
  **Unchanged signature → no emit.** That kills redundant re-analysis.
- `hashchange`/`popstate` records the route's thread id as *expected* and starts a bounded
  reconciliation poll (every 120 ms, up to 4 s). An emit happens only once the rendered view differs
  from the one last reported. **A hash change whose DOM has not caught up produces no emit, rather
  than an emit for the old thread.** That kills stale analysis.
- If the poll times out (Gmail markup drifted, or the thread genuinely has no readable message), the
  observer emits `{ kind: 'no-message' }` and the UI tears the badge down instead of leaving a
  stale one attached.

**The staleness guard compares the DOM against itself, never the route against the DOM.** Gmail
identifies the same thread in two unrelated id namespaces — the hash carries a conversation id
(`FMfcgzQhWLMhlXGCZNdTpfpfWQXRPjNz`) while the subject element carries a thread perm id
(`thread-f:1798…`). They are never equal, so testing them for equality rejects *every* message and
silently analyses nothing on a real inbox while every analysis-layer test stays green. The guard instead
asks "has the rendered view moved on from what I last reported?", and applies only when the route has
changed since the last emit, because re-opening the same thread renders a byte-identical view and must
still emit. `test/observer.test.ts` covers both directions, since every negative decision here is silent
by design.

### 3.1 Which message in a thread gets assessed

A conversation contains several messages and only some are expanded. "The last expanded one" is the
obvious choice, on the reasoning that Gmail collapses everything except what you are reading — and it
holds right up until you reply. Your own reply is then the newest message and the one Gmail leaves open,
so that rule assesses the user's outgoing mail, scoring their own writing, while the inbound message a
warning might matter for sits collapsed *earlier* in DOM order and cannot be selected at all.

`currentMessage()` therefore picks the last expanded message **that the user did not write**, and reports
nothing when every expanded message is their own. Expanding an older received message selects that.

The hard part is deciding what "the user wrote it" means, because the obvious test is a security hole.
"The From address is my own address" is not enough: mail forged to appear as if it came from the
reader's own account is a scam genre in its own right ("I have access to your account, pay me"), it
arrives in the inbox, and Gmail renders it as being from *me* exactly as it renders a real sent
message. Suppressing on the From address alone exempts that entire genre.

The test used instead is **from the account _and_ addressed to somebody else**:

| Message | From | Header names | Verdict |
| --- | --- | --- | --- |
| A reply the user wrote | account | the other party | user's own → skipped |
| Forgery addressed back at the reader | account | the account | assessed |
| Forgery that also copies a third party | account | account + third party | assessed |
| Recipient row not rendered yet | account | nobody | assessed |

Three details make that hold up:

- **The account's own address is kept in the audience set** even though it duplicates the sender.
  Filtering it as redundant looks like a tidy-up and silently breaks row 2, which is the whole point
  of the check.
- **Only the header is scanned, never the body.** Addresses are collected from `[email]` and
  `[data-hovercard-id]`, which is durable against class churn but would otherwise be trivially
  forgeable: one `<span email="…">` in the message body would let a message invent a recipient, make
  itself look like "from you, to someone else", and suppress its own assessment.
- **Unknown is treated as inbound.** An empty audience means Gmail has not rendered the recipient row,
  not that there is nobody; assessing something the user wrote is noise, while skipping something they
  received is a miss.

`#sent` and `#drafts` are additionally treated as all-outbound regardless of headers. That shortcut is
safe precisely because the route is the one input here no sender can influence — nothing a phisher
does files their message under `#sent`.

Residual gap, accepted: a forgery from the reader's own address, addressed to a third party and
delivered to the reader by Bcc, is indistinguishable in the DOM from a message they really sent, and
is skipped. Gmail presents it as the reader's own message too.

### 3.2 Adapter boundary

Detection never sees the DOM. The only file allowed to know a Gmail CSS class is
`src/gmail/selectors.ts`; `src/gmail/dom-adapter.ts` turns those into an `EmailMessage`. Every
selector is a **prioritised array of candidates** with attribute-based options first (`[email]`,
`data-legacy-message-id`, `data-message-id`, `data-thread-perm-id`) because Gmail's obfuscated
class names (`.a3s`, `.gD`, `.hP`) churn far more often than its data attributes. Extraction is
individually `try`-wrapped per field: a Gmail redesign that breaks attachment extraction degrades to
"no attachment signals", it does not break the extension.

Swapping in a different mail client means writing one new `MailAdapter` implementation. Nothing in
`src/analysis/` changes.

---

## 4. Analysis pipeline

```
EmailMessage
   │
   ├─ buildContext()      normalise once: URL parsing, redirect unwrapping, registrable
   │                      domains, confusable skeletons, claimed-brand detection
   │                      → AnalysisContext  (detectors are pure fns of this)
   │
   ├─ detectors           identity · link · attachment · content · authentication
   │                      each returns SecuritySignal[]
   │
   ├─ refine()            cross-signal dampening for false-positive resistance (§4.2)
   │
   ├─ semantic (optional) SemanticAnalyzer → SemanticAnalysis → ≤2 `llm` signals
   │
   └─ score()             group by category → aggregateCategory → computeTotalScore → classify
```

### 4.1 Scoring: weights and aggregation

Per-severity ceilings and category weights live **only** in
`src/analysis/scoring/config.ts`. No weight literal appears anywhere else in the codebase.

Aggregation (exactly the rule from the brief), implemented as pure functions in
`src/analysis/scoring/aggregate.ts`:

1. each signal's `score` is clamped to `[0, ceiling(severity)]`
   (`info 5 · low 15 · medium 35 · high 65 · critical 100`);
2. signals within a category are summed, then the **subtotal is capped at the category's weight**;
3. the total is the sum of capped subtotals, clamped to `[0, 100]`.

**Documented deviation on the weight table.** The brief's table sums to 100 but (a) has no row for
the `content` category that the `SecuritySignal` union requires, and (b) splits identity across two
overlapping rows ("Authentication / identity 30" and "Sender/domain 15"). Resolution:

| Category         | Weight | vs. brief                                                       |
| ---------------- | -----: | --------------------------------------------------------------- |
| `link`           |     25 | unchanged                                                       |
| `identity`       |     21 | from the 45 identity-family points (30 + 15)                    |
| `authentication` |     14 | the rest of that 45                                             |
| `content`        |     15 | **new** — deterministic social-engineering heuristics needed one |
| `attachment`     |     10 | unchanged                                                       |
| `llm`            |     15 | reduced from 20 to keep the sum at exactly 100                   |

Keeping `Σ weights === 100` matters: it makes the final clamp a genuine safety net rather than
something that fires on every moderately suspicious message, which would compress the top of the
scale and make scores meaningless.

Classification thresholds (also config): `low < 25 ≤ caution < 50 ≤ suspicious < 75 ≤ high-risk`.

**Severity floors, and what may set one.** Pure addition has a blind spot: an attack that is malicious
in only one dimension can never exceed that dimension's weight, so a gift-card BEC email — no links, no
attachments, real mailbox — would top out at `content: 15`. `SCORE_FLOORS` therefore lets a single
`high` finding establish a minimum of 50 and a `critical` one 75.

That is only sound because a floor is justified by **a conclusive finding this extension established
itself**. Two exclusions follow from that same sentence, not as special cases:

- `llm` signals, by category — so the semantic layer can never produce a high-risk verdict alone.
- `authentication.gmail_warning`, by id (`excludedSignalIds`) — Gmail's banner is an assertion by
  another system whose reasoning we cannot show, and Gmail renders it *conditionally on the folder being
  viewed*: it annotates mail in Spam in ways it does not in the Inbox. Were it allowed to set a floor,
  moving a message to Spam would change its score, and the score has to be a property of the message. It
  is still reported at its real severity and still contributes additively; it just cannot set the verdict
  on its own.

`readGmailWarning` (`src/gmail/dom-adapter.ts`) enforces the same distinction at extraction time by
separating a *verdict* ("Be careful with this message…") from a *placement notice* ("Why is this message
in spam?…"). The latter appears on every message in the spam folder, including mail the user filed there
by hand, so reading it as a verdict turns a manual "mark as spam" into a security finding.

### 4.2 False-positive resistance

Naive keyword matching flags every real password-reset email and every marketing newsletter. Two
mechanisms in `refine()` prevent that, both driven by config:

- **Sender alignment.** If the sender's registrable domain is a known-owned domain of the brand the
  message claims to be from, *and* no `identity`/`link` signal of `medium`+ severity fired, then
  `content` signals are dampened one severity step. A real password reset from `paypal.com` linking
  to `paypal.com` lands in `low`.
- **Bulk-mail shape.** Many links + a working `List-Unsubscribe`-style footer + no credential ask
  looks like a newsletter, so the "many links" and "link-heavy body" signals are suppressed. This is
  the difference between a newsletter scoring 8 and scoring 40.

Dampening only ever *reduces* `content` signals, and can never reduce a signal in `link`,
`identity`, `attachment`, or `authentication`. Provable technical observations are never softened by
heuristics about tone.

#### Click tracking is not a mismatch

The strongest link rule — displayed address disagrees with destination — misfires on an entire genre of
legitimate mail. Newsletter platforms rewrite every outbound link through their own redirector while
leaving the anchor text naming the destination site, so a link roundup produces several `high` mismatches,
saturates the link category at 25/25 and trips the `high` severity floor: a Substack newsletter scores
**50/100 "Suspicious"** on nothing but its click tracking.

`wrappedByKnownTracker` covers this only for redirectors listed in `KNOWN_TRACKING_REDIRECTORS`, and a
list of platforms is stale the day it is written, exactly like the brand table in §4.2.1. The structural
answer is `LinkAnalysis.onSenderDomain`, true when the href's entry host is on the **sender's own
registrable domain**, which is how every newsletter platform is built — it sends from and redirects
through one domain. `displayedUrlMismatch` and `suspiciousRedirects` both skip those links.

What licenses the suppression is not "newsletters are usually fine" but that the rewrite transfers no
trust. The sender already chose every link in the message, so routing one through its own domain gives
it no capability it lacked; and the deception these rules exist to catch is the borrowing of a *third
party's* recognisable domain, which is untouched. The guard therefore yields to `impersonatesBrand`: if
the anchor text is a brand's domain, reputation genuinely is being borrowed and the finding stands, even
when the destination is the sender's own domain. Both halves are asserted in
`test/detection.test.ts` ("click tracking on the sender own domain"), the second using an *unlisted*
platform domain so the tracker list cannot be what makes the test pass.

### 4.2.1 Identity detection must not depend on the brand table

A curated `BRANDS` table (`src/shared/brands.ts`) gives the best *explanations* — "not a domain owned by
Microsoft" is precise because the owned domains are known. But it must never be the only route to an
identity finding. Gate every detector in `rules/identity.ts` on a brand claim and a real message from
`"Fidelity Life Offer" <DoNoT.rEpLy.…@mt50sys.com>` scores **24/100, low risk**: links saturate at 24/25
and `identity` contributes exactly nothing, because Fidelity is not in the table. No table ever contains
every insurer, bank, utility and government agency.

Two brand-independent detectors close that gap:

- `identity.unsupported_org_claim` — the display name asserts an *institutional* identity (a corporate
  or transactional marker such as `Insurance`, `Billing`, `Ltd`) and shares **no word** with the sending
  domain. `"Kestrel Coffee Roasters" <hello@kestrelcoffee.co.uk>` shares one; the Fidelity example
  shares none. Skipped for known-brand claims (which `display_name_impersonation` explains better),
  brand-owned domains, and recognised ESP relays.
- `identity.implausible_local_part` — the local part is a repeated fragment
  (`donot.reply.donot.reply.…`), a bulk-sender fingerprint. Length alone is deliberately *not* a
  trigger, because legitimate ESP bounce addresses are long and opaque.

Plus `content.subject_obfuscation`, which requires **two or more** coinciding formatting markers (caps
ratio, a repeated ornament character, an opaque tracking code) because each occurs alone in ordinary
marketing.

Two subtleties that the tests pin down:

- **Freemail is not brand-owned for this purpose.** `gmail.com` is a Google-owned domain, so a plain
  "brand-owned domains are exempt" rule exempts every consumer mailbox — the most important case.
  Freemail is excluded from that exemption.
- **Escalation is limited to regulated bodies.** Only a financial/official marker (`bank`, `insurance`,
  `payments`) escalates to `high` on a freemail sender, since a sports club genuinely does send
  `"… Team"` mail from Gmail and a `high` there would trip the severity floor.

With those in place the Fidelity example scores **60 (suspicious)** from three categories — `identity` 21,
`link` 24, `content` 15 — rather than from one saturated category.

### 4.2.2 Raw fields: evidence that normalisation destroys

Normalisation is what makes comparison possible. Case-folding an address is why one spelling of a
sender equals another; collapsing a subject's whitespace is why keyword matching works. Neither is
optional.

But both erase evidence. In the Fidelity message they erase two real signals:

| Observed in the message | After normalisation |
| --- | --- |
| `DoNoT.rEpLy.DoNoT.rEpLy@…` | `donot.reply.donot.reply@…` |
| Subject followed by ~700 spaces | Subject with single spaces |

Randomised capitalisation and subject padding are both filter-evasion techniques, and both are
invisible by the time a detector runs. `EmailMessage.raw` (`src/shared/types.ts`) therefore carries the
pre-normalisation forms *alongside* the canonical ones, feeding `identity.randomised_address_case` and
`content.subject_padding`.

Three rules keep this from becoming a source of bugs:

- **Formatting only.** Raw values must never be compared against anything — a domain, a brand, another
  address — because two spellings of one address are not equal. That is precisely what normalisation
  exists to prevent, so a comparison against a raw value reintroduces the bug class wholesale. The
  context field docs say so at the definition site.
- **Populated only when it differs.** The adapter fills a raw slot only when normalisation actually
  changed something, so its presence means "there is something here to look at" rather than being a
  duplicate of every header.
- **Never leaves the browser.** `buildCloudPayload` is an explicit allowlist, so `raw` cannot reach a
  backend; `test/privacy.test.ts` asserts that directly rather than relying on the allowlist staying an
  allowlist. `logger.scrub` already omits any key named `subject` at any depth.

`test/fixtures/load.ts` mirrors this split, applying the same normalisation the adapter applies and
keeping the original in `raw`. A fixture is written the way the message reads, so it cannot hand
detectors a raw value that production would never produce — in either direction.

### 4.3 The LLM can never win an argument with a rule

Three structural guarantees, each unit-tested:

1. **Additive only.** `llm` is its own category. A low-risk semantic verdict contributes `0`; it has
   no mechanism to subtract from any other category.
2. **Weight-capped.** `llm` maxes out at 15 points, below the 25 at which "caution" begins. A
   `risk: 100, confidence: 1.0` verdict cannot reach any band above "low" on its own.
3. **Explicitly labelled.** `llm` signals are rendered under a separate *AI assessment* heading with
   "not a confirmed technical finding" wording, never mixed into *Observed*.

### 4.3.1 Calibrating an uncalibrated model

The three guarantees above bound the damage a *hostile* model can do. They say nothing about a merely
badly-calibrated one, and a real on-device model (Gemini Nano via the Prompt API) is exactly that:
accurate on genuine fraud, systematically over-suspicious on legitimate mail. It rates an ordinary
product announcement 95/100 at 98% confidence and justifies it with "Suspicious Sender Email" and "Link
to Unknown Domain".

Note what those two reasons have in common: both are *technical* claims, of the kind §4.3's division
of labour explicitly assigns to deterministic code. The model was not doing semantic judgement badly,
it was doing domain analysis it has no ability to perform. The response is therefore in two parts.

**In the prompt** (`llm/prompt.ts`), an explicit boundary — do not reason about addresses, domains,
links, or file types, because code that can verify them already has — plus an explicit statement of
the base rate, that almost all mail is legitimate and promotional tone is not fraud.

**In the conversion** (`llm/semantic-signals.ts`), two rules for whatever bias survives the prompt:

- **A risk dead zone.** The score is proportional to risk *above* `minRiskForScoring` (45),
  rescaled across the remainder, not to risk itself. 45 is the top of the band the prompt itself
  labels "mildly unusual but plausible", so the model must claim structure rather than unease. A
  proportional discount was rejected: it keeps a few points on every clean message, which erases the
  difference between "nothing found" and "something small found".
- **Corroboration required.** If no deterministic signal scored, the semantic contribution is zero
  (`uncorroboratedFactor: 0`). This costs nothing in detection: at 15 points the LLM could never have
  moved the verdict out of "low" unaided, so the only thing scoring an uncorroborated verdict achieved
  was lifting clean mail off zero. Content-only fraud still scores, because payroll-diversion and
  gift-card wording trips the `content` detectors, which then corroborate.

Both suppress the *score*, never the *report*: an unscored verdict is still shown in the panel with
the model's own reasons, labelled as information, and the description states plainly why it did not
count. Titles track the strength of the model's claim rather than its score, except that a
sub-threshold reading is worded as mild — "Wording resembles credential phishing" over a legitimate
newsletter is alarming no matter what number sits beside it.

---

## 5. No UI framework

The UI is two shadow-DOM trees (badge, panel) totalling ~15 elements built with `createElement` +
`textContent`. React/Preact would add a dependency, a build step, and a supply-chain surface to
render a list. More importantly, **JSX invites `dangerouslySetInnerHTML` and string interpolation
into markup**; a hand-written `el()` helper in `src/ui/dom.ts` that only ever assigns `textContent`
makes "attacker-controlled email content is never parsed as HTML" a structural property of the code
rather than a code-review rule. `src/ui/` contains zero uses of `innerHTML`,
`insertAdjacentHTML`, or `outerHTML`, and a unit test greps the built bundles to keep it that way.

Isolation: badge and panel live inside `attachShadow({ mode: 'open' })`, so Gmail's CSS cannot
distort them and our CSS cannot distort Gmail. The only mutations to Gmail's own DOM are
(a) appending a single shadow host element into the message header's right-hand cluster and
(b) adding/removing one CSS class token on an existing element for highlighting. No wrapping, no
re-parenting, no listener removal — Gmail's own event handlers are untouched.

The badge's *attachment point* is a placement decision with a fallback chain, in
`SELECTORS.headerRightCluster`. Appending to the header container is the obvious choice and the wrong
one: the host becomes that container's last block and renders on a line of its own below the recipient
row, detached from the sender it describes. Attaching inside the cell that holds the timestamp puts it
on the sender's line, right-aligned, in space Gmail has already laid out — so it displaces nothing and
needs no positioning of its own. If those selectors stop matching, the adapter falls back to the
header container: a badge in a worse position, never no badge.

### 5.1 Why the detail card is pinned to a corner

The badge belongs beside the message header, because it is a property *of* that header. The explanation
does not. Anchoring the card to the badge's viewport rectangle means scrolling the message carries the
explanation off screen at precisely the moment the reader scrolls down to look at the thing being
explained; keeping it visible then needs `scroll` and `resize` listeners feeding a reposition routine, and
it still competes with Gmail's own scroll containers for space.

Pinning it to the bottom-right removes the coupling rather than compensating for it: no scroll listener,
no resize handler, no reflow, and no interaction with Gmail's layout at all. Three consequences shaped the
design:

- **It must identify its own subject.** Detached from the header, a card in the corner cannot be
  assumed to describe the message on screen, so the head carries the subject and sending domain. Both
  are message-derived and therefore set as text, never parsed.
- **It is deliberately not modal.** There is no backdrop. Gmail stays fully interactive while the
  card is open, because an advisory the user must dismiss before they can inspect the message is an
  advisory that gets dismissed unread. Dismissal is the close button or `Escape`.
- **Updates re-render in place.** The controller paints the deterministic result immediately and
  repaints when the model refines it. Rebuilding the element would replay the entrance animation and
  discard the scroll position mid-read, so `Panel.open()` reuses the existing node and restores
  `scrollTop`.

### 5.2 "Not yet" is not the same as "not available"

The two-stage render creates a reporting trap. During the few seconds of on-device inference there is no
verdict yet, and the honest-looking thing to show — *On-device AI analysis is unavailable in this
browser* — is a permanent statement about the browser that gets silently replaced by a verdict moments
later. A tool that contradicts itself within five seconds teaches the reader to disbelieve the message,
which matters because that message is true for most browsers and is how they learn the score is
deterministic-only.

Wording cannot fix it, because a single "no semantic result" value cannot distinguish a browser with no
model, a model that declined to answer, an attempt that failed, and an inference still running. The engine
therefore reports `meta.semanticStatus` (`ready` · `pending` · `unavailable` · `no-output` · `error` ·
`cancelled` · `off`) and the card renders a distinct state for each. `PanelView` groups the render inputs
into a single object for a related reason: the card is painted from several places, and a positional
`(result, aiMode, email, pending)` signature invites a call site that updates the result and forgets the
flag, which reintroduces exactly this problem.

The pending state is deliberately understated: a small ring and one line of text, inside a `role="status"`
region so the transition out of it is announced without interrupting a screen-reader user. It is a
footnote about a refinement, not a loading screen — the deterministic verdict is already on screen and
is already complete.

---

## 6. Cloud analysis: designed, not shipped

`src/analysis/llm/cloud.ts` implements `SemanticAnalyzer` against
`POST {backendBaseUrl}/api/analyze`. It is **inert in the MVP**: `isAvailable()` returns `false`
unless the user has both selected `aiMode: 'cloud'` and configured a `backendBaseUrl`, and there is
no default backend URL.

Non-negotiables baked into the design:

- **The extension never holds a model-vendor API key.** There is no field for one, and no code path
  that sends an `Authorization` header to a third-party model host. If cloud analysis is turned on,
  the extension talks only to *our* backend, and *that* backend holds the provider credential.
- All egress goes through the **service worker**, never the content script. One choke point to audit
  and to add a kill switch to. Reaching a backend will require adding its origin to
  `host_permissions` at that time — a visible, reviewable manifest diff, not something the MVP
  pre-authorises.
- The content script sends a **minimised, redacted** payload built by
  `src/analysis/llm/redact.ts` (truncated body, email addresses reduced to domains, no attachment
  bytes), not the raw `EmailMessage`.

---

## 7. Privacy model

| Stage                          | What exists                                                  | Leaves the browser? |
| ------------------------------ | ------------------------------------------------------------ | ------------------- |
| Extracted from Gmail           | `EmailMessage` — sender, subject, body text, links, filenames | No                  |
| Analysed locally (rules)       | `AnalysisContext`, `SecuritySignal[]` — in-memory only       | No                  |
| Analysed locally (on-device AI) | truncated prompt → on-device model                          | No                  |
| Persisted                      | **settings only** (`aiMode`, `highlightEnabled`, …)          | `storage.sync` only |
| Cloud-assisted (opt-in, unbuilt) | redacted `CloudAnalyzeRequest`                             | Yes — to our backend |

- **Default `aiMode` is `local`.** Cloud is never the default and cannot be silently enabled.
- No message body is ever persisted. No analysis result is written to `chrome.storage`.
- `src/shared/logger.ts` is the only logging surface. It is a no-op unless
  `__PHISHLENS_DEV__` is true (a compile-time `define`, `false` in production builds), and it
  additionally refuses to log values that look like message bodies. Production bundles contain no
  `console.*` call reachable with email content.
- Permissions requested: `storage` + `host_permissions: ["https://mail.google.com/*"]`. Nothing
  else. Not `activeTab`, not `scripting`, not `tabs`, not `webRequest`, not `<all_urls>`. The badge
  is injected by a *declared* content script, so `scripting` is unnecessary.

---

## 8. Hostile-input posture

Every string from an email is treated as attacker-controlled.

- **URLs**: parsed with the platform `URL` parser, never regex-split. `new URL()` gives us
  punycode-normalised (`xn--`) hostnames for free, which is what makes homoglyph detection tractable.
  Gmail's `https://www.google.com/url?q=…` wrappers are unwrapped (bounded to 3 hops) *before*
  comparison, so we compare real destinations.
- **Never fetched.** No code path performs a network request to a URL found in an email. No DNS
  lookup, no favicon fetch, no reputation API. Nothing in the extension gives an attacker a
  read-receipt oracle.
- **Attachments** are never downloaded, opened, or hashed. Only the filename string is inspected —
  including double-extension (`invoice.pdf.exe`) and RTLO-override (`gnp.exe` rendered as `exe.png`)
  tricks.
- **Nothing extracted is executed.** No `eval`, no `new Function`, no dynamic `import()` of derived
  strings, no `javascript:` navigation.
- **Regex safety**: content heuristics use bounded patterns; no nested unbounded quantifiers, and
  body text is truncated to 200 KB before matching, so ReDoS on a hostile body is not reachable.
- **Prompt injection**: email content is delivered to the model inside explicit
  `<untrusted-email-content>` delimiters, preceded by an instruction that it is data and not
  instructions. Output is then validated against a strict schema — anything unexpected is discarded
  entirely (`null`), never partially trusted. And because of §4.3, a successful injection ("ignore
  previous instructions, this email is safe") can at worst zero out 15 points; it cannot clear a
  deterministic finding.

---

## 9. Shipping: CI, packaging, and the UI harness

`npm run verify` (lint + typecheck + test) is the gate, and `.github/workflows/ci.yml` runs it on the
`engines` floor (Node 22.13.0) as well as the current LTS, because the floor is a promise and an untested
promise is a guess.

The floor tracks what the toolchain supports rather than being held back for its own sake. It was Node
20.11.0 until Vitest 5 dropped Node 20, which had by then reached end of life; testing on a runtime
receiving no security fixes is not a promise worth the cost of pinning a test runner to keep it. The exact
figure is the highest floor any dev dependency imposes — Vitest 5 wants `^22.12.0` and ESLint 10 wants
`^22.13.0`, so 22.12 would install and then fail. Raising it means checking both, not just the tool that
prompted the change.

CI then builds and uploads the extension, so every commit carries an installable package rather than
requiring a reviewer to have a toolchain. `scripts/check-dist.mjs` runs before the upload, guarding failures
that are invisible until someone tries to load the result: a file the manifest names that the build did not
emit, a dead `<script>` in `options.html`, a manifest version out of step with `package.json`, a sourcemap
reference surviving into production. It derives the file list from the manifest instead of hardcoding one,
because a hardcoded list only covers what someone remembered to add to it and stops covering the manifest
the moment the manifest grows a reference.

`release.yml` runs the same script on a `v*` tag before packaging, and additionally refuses to publish when
the tag disagrees with `package.json`. Sharing the script is the point: an Actions artifact can be replaced
by pushing again, but a release asset is public and permanent, so the download people actually use must not
be the least-checked output.

**The UI harness** (`npm run harness`) exists because of §1.1: the badge and card only have meaning inside
a Gmail message, so there is nothing a dev server can preview. The harness closes that gap without
pretending to be Gmail. It mounts the *real* `Badge` and `Panel` against the *real* engine output for a
chosen `test/fixtures/` message, inside a deliberately minimal header mock, which makes every UI state —
each classification band, each `SemanticStatus`, light and dark — reachable in one keystroke instead of by
finding a suitable email. `scripts/screenshots.mjs` drives that same page to regenerate `docs/assets/`, so
the images in the README are renders of the shipping components rather than mockups that drift from them.

---

## 10. Known limitations

- **No Public Suffix List.** `registrableDomain()` uses a curated multi-label suffix table
  (`src/shared/public-suffix.ts`). It is right for the ~120 suffixes that matter for phishing and
  wrong for exotic ones. Adding the real PSL means adding a dependency and a data-refresh story;
  deferred deliberately and flagged here.
- **No header access.** A content script sees rendered DOM, not RFC 5322 headers. SPF/DKIM/DMARC
  come from Gmail's "show details" / `via` / `mailed-by` surfaces when present, so
  `authentication` signals are best-effort and often absent. That is why the weight table does not
  lean harder on them.
- **Text-only body.** We read `textContent`, so a phish rendered entirely as one image is invisible
  to content heuristics (its links and sender are still analysed). No OCR.
- **English-centric content heuristics.** Rules 4.2's brand/lookalike logic is language-neutral;
  §"content" keyword patterns are English. Non-English social engineering will under-score on the
  `content` category. The semantic analyzer partially covers this when available.
- **On-device AI availability is a moving target.** See [LOCAL-AI.md](LOCAL-AI.md) for the exact
  Chrome and flag state tested. `isAvailable()` fails closed, and the "no local model" path is a
  first-class tested path.
