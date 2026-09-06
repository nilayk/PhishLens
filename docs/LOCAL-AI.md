# The semantic layer

What the language model is asked, what it is allowed to change, and why it is on such a short leash.
Design reasoning is in [ARCHITECTURE.md §2.2 and §4.3](ARCHITECTURE.md).

## One interface, three implementations

```ts
interface SemanticAnalyzer {
  isAvailable(): Promise<boolean>;
  analyze(email: EmailMessage, options?: { signal?: AbortSignal }): Promise<SemanticAnalysis | null>;
}
```

`ChromePromptAnalyzer` (Chrome's built-in model, shipped), `ModelServerAnalyzer` (a model server the user
runs, shipped) and `CloudAnalyzer` (designed, inert) implement the same interface, so the analysis,
scoring, and UI layers cannot tell which one produced a verdict — or whether one ran at all. The card
names the source, which is the only place the difference is visible.

The model returns structured data, never prose:

```ts
interface SemanticAnalysis {
  risk: number;                  // 0-100, advisory
  categories: SemanticCategory[]; // from a fixed enum
  reasons: string[];             // short justifications, rendered as text
  confidence: number;            // 0-1
}
```

## Three containment guarantees

These are arithmetic, not convention, and each is covered in `test/semantic.test.ts`.

1. **The cap.** The `llm` category is worth 15 of 100 points and contributes additively. A model that has
   been successfully prompt-injected into declaring a phishing email safe changes the score by at most 15
   points downward from where it would otherwise be. It cannot remove a deterministic finding, cannot
   lower the score past a deterministic floor, and cannot change the classification of a message that
   failed a technical check.
2. **No origination.** A verdict that no deterministic signal corroborates scores **zero**
   (`uncorroboratedFactor: 0`). The model may sharpen a score; it may not invent one. Dampened signals do
   not count as corroboration, so a finding deliberately softened elsewhere cannot license points here.
3. **Separation in the UI.** Model output is rendered in its own section, labelled as an assessment rather
   than an observation, with the model's own reasons shown. A reader can always tell which half of the
   card is checkable.

Suppressing an uncorroborated score costs no detection capability, which is what makes it the right call
rather than merely a cautious one: 15 points is already below the `caution` threshold of 25, so an
uncorroborated verdict could never change the classification even at full weight. All that scoring it
achieved was moving the number off zero on clean mail, which destroys the difference between "we found
nothing" and "we found something small".

## Calibration

On-device models are accurate on genuine fraud and markedly over-suspicious on legitimate mail. Gemini
Nano will rate an ordinary product announcement 95/100 at 98% confidence and give "Suspicious Sender
Email" and "Link to Unknown Domain" as its reasons — both claims about domains, which is not something it
can check and not something it was asked about. Told in the prompt not to reason about domains and shown
them regardless, it did so anyway: a genuine bank notification scored 85/100 on the reasoning that one of
its links was not specific enough to the bank's own site.

Four responses, in the order they apply:

- **The model is not given the subject matter it must not judge.** It receives the sender's display name,
  the subject and the body — nothing else. No sending domain, no Reply-To, no link destinations, no
  attachment types. An instruction it cannot follow is worth less than data it cannot see, and everything
  withheld is checked properly, from the real values, in `analysis/rules/`.
- **A dead zone.** Any verdict below `minRiskForScoring` (45/100) scores zero regardless of confidence.
  Below `routineRiskCeiling` (20/100) the finding is also *worded* as clean, because models fill the
  category slot as a matter of form: one rated an auto-reply 10/100, explained itself with "standard
  auto-reply", and tagged it `social_engineering` anyway.
- **Corroboration.** Guarantee 2 above.
- **Explicit guidance for the mail most often misjudged.** Security and account notices — a password was
  changed, a device signed in, a statement is ready — read like credential phishing to a model that
  weighs vocabulary, and are the largest single source of false alarms on real mail. The prompt states
  that reporting an event that already happened is routine, and that directing the reader to a channel
  they already have (the number on their card, the app) is the opposite of phishing, since an attacker
  gains nothing from it.

The verdict is displayed in full either way. It just does not always move the number.

## Chrome's Prompt API

`src/analysis/llm/chrome-prompt.ts` targets Chrome's built-in Prompt API. **That API is unstable, and
the code treats it as such.** Across versions the entry point has been `window.ai.languageModel`,
`chrome.aiOriginTrial.languageModel`, and the current bare `LanguageModel` global; availability has been
reported as `capabilities().available` (`'no'` / `'after-download'` / `'readily'`) and as `availability()`
(`'unavailable'` / `'downloadable'` / `'downloading'` / `'available'`); and it is commonly gated behind a
flag, hardware requirements, or an origin trial.

One consequence is worth stating plainly, because it is a trap: the current entry point is a **class**, so
`typeof LanguageModel === 'function'`. A probe that checks `typeof === 'object'` before reading properties
— the natural way to write a defensive one — rejects the live API on every browser that has it, fails
closed, and reports "no on-device model" with complete conviction. The fakes in
`test/chrome-prompt.test.ts` are therefore function-typed with static methods, mirroring the browser's
shape rather than merely its interface, because object-literal fakes cannot distinguish a working adapter
from a broken one.

### Trying it with a real model

Development targeted the Chrome 138+ `LanguageModel` global as the primary path, with Chrome ≥ 120 as the
manifest minimum. To exercise a real model rather than the fakes you need a build where Gemini Nano is
available, which currently means enabling `chrome://flags/#prompt-api-for-gemini-nano` and
`chrome://flags/#optimization-guide-on-device-model` and waiting for the download. Expect this to drift;
the detection code is written so that drift degrades to "unavailable" rather than to a crash.

A `downloadable` or `downloading` model is deliberately treated as **unavailable**. Opening an email
should not start a multi-hundred-megabyte download.

## When there is no model

The common case, and it is a supported one rather than a degraded one. `isAvailable()` fails closed: a
missing global, an unexpected shape, or a thrown error resolves to `false` and never propagates. The
pipeline produces a complete, correctly classified result with the `llm` category contributing exactly
zero, and the card *says* the model did not run — silence would let a reader assume the AI approved the
message.

### Seven statuses, because "no assessment" has several causes

`meta.semanticStatus` distinguishes them, and the card words each differently:

| Status | Meaning |
| --- | --- |
| `ready` | An assessment was produced. |
| `pending` | Inference is in flight; the score on screen may still change. |
| `off` | The user switched AI analysis off. |
| `unavailable` | No model in this browser, or no server/backend configured — nothing was sent. |
| `no-output` | The model ran and returned nothing that passed schema validation. |
| `error` | The model is present but this attempt failed — a timeout, or a rejected session. |
| `cancelled` | The attempt was abandoned because the reader moved on. |

The distinction between `pending` and `unavailable` is the one users notice. Inference takes a few
seconds, during which the deterministic score is already complete and on screen. Showing "unavailable in
this browser" and then replacing it with a verdict seconds later would teach a reader to disbelieve that
message in the case where it is true, so the card shows a progress indicator for that window instead.

**An interrupted assessment is retried, not remembered.** Only `ready` and `off` may be cached
(`isSemanticSettled`), because a cache hit short-circuits before the model is ever asked — so caching a
non-answer would make it permanent for the life of the tab. A cancelled attempt, a one-off timeout, and a
message read while Chrome was still downloading the model are all re-assessed on the next visit.

## Operational rules

- Deterministic settings are requested where supported (`temperature: 0`, `topK: 1`), and a JSON schema
  constraint where supported, with an unconstrained retry where it is not.
- Output must be JSON matching the schema. Validation is all-or-nothing: a malformed response yields
  `null`, never a partially salvaged object, because a model that returned a malformed object is a model
  whose values are not trustworthy either — and a hostile email may well be the reason it is malformed.
- One inference has a 20-second timeout, after which the session is discarded and rebuilt.
- **One prompt at a time.** A session rejects a second `prompt()` while the first is outstanding, and this
  adapter treats a rejected inference as a poisoned session, so two overlapping calls do not degrade to
  one winning — they both fail. This is reachable in normal use, because Gmail renders a thread in stages
  and the first message opened after a page load is reported two or three times. Model work is serialised
  through a queue and superseded messages are cancelled via `AbortSignal`.
- If the API only accepts a bare `create({})` with no system prompt, the system prompt is prepended to the
  user prompt instead, so no session is ever uncalibrated or uncontained.
- The session is built at startup (`warmUp()`) rather than on first use, so its several seconds are spent
  while the reader is still looking at their inbox. Warming never downloads a model.
- The session is cached in the **content script**, never the service worker, which MV3 may terminate at
  any moment.

## Your own model server

Chrome's built-in model is small, and its over-suspicion on ordinary mail is a consequence of that. A 7B
or larger instruction-tuned model, which most machines can now run, is markedly better at the one question
this layer asks. `aiMode: 'server'` uses one you run yourself.

**It buys better reasons, not more weight.** Every guarantee above still holds unchanged: 15 points, no
origination, the same dead zone, the same separation in the UI. A 70B model on your own GPU is bound
exactly as Gemini Nano is, and `test/semantic.test.ts` asserts it for that source specifically. If a
larger model could outvote the deterministic checks, then the checks would be the thing worth fixing.

### One request shape for every runner

They all speak OpenAI's `/chat/completions`, so there is one adapter rather than one per runner. Paste the
base URL exactly as your runner documents it; `/chat/completions` is appended.

| Runner | Base URL | Notes |
| --- | --- | --- |
| Ollama | `http://localhost:11434/v1` | Needs `OLLAMA_ORIGINS` — see below |
| LM Studio | `http://localhost:1234/v1` | Start the server from the Developer tab |
| Docker Model Runner | `http://localhost:12434/engines/v1` | Requires host-side TCP to be enabled |
| llama.cpp / vLLM / LocalAI | as configured | Anything OpenAI-compatible works |

**Ollama refuses browser-origin requests by default,** and this is the first thing that goes wrong for
everybody. Set `OLLAMA_ORIGINS` to include the extension before starting it:

```bash
# macOS / Linux
OLLAMA_ORIGINS='chrome-extension://*' ollama serve
```

```powershell
# Windows: set it for the user, then restart Ollama from the tray
setx OLLAMA_ORIGINS "chrome-extension://*"
```

LM Studio has an equivalent CORS toggle in its server settings. Naming your own extension id rather than
`chrome-extension://*` is stricter and worth doing if you keep the setting permanently.

Structured output is requested as `json_schema` first, then `json_object`, then not at all, because
coverage differs by runner and version and a server that does not recognise a `response_format` rejects
the request rather than ignoring the field. Each retry is a rejected request rather than a wasted
generation, so this costs a round trip on old servers and nothing on current ones.

### What is sent, and what that costs

The prompt is **byte-for-byte the on-device prompt**: display name, subject, body excerpt. Not the link
targets, not the sending domain, not the attachment types, not the recipient address — the same
withholding described under Calibration, for the same reason. There is no `Authorization` header and no
field for a key, so this cannot be pointed at a hosted vendor and used as a key-bearing client.

Plain `http://` is accepted **only for `localhost`, `127.0.0.1` and `[::1]`**, where there is no wire to
intercept. Any other host must be `https://`: the request carries the text of the message you are reading,
and sending that in the clear across a LAN would be a worse leak than most things this extension warns
about. `test/privacy.test.ts` pins both halves of that rule, including that `http://localhost.evil.example`
is not loopback.

Access to the server is an **optional host permission**, requested for that one origin when you press
Connect, and handed back when you change the address. A default install still asks for `storage` and
`https://mail.google.com/*` and nothing else — a blanket `http://*/*` in `host_permissions` would make
every user pay a permission for a feature most will not enable.

The timeout is 45 seconds, against 20 for the on-device model, because the work is happening on your
hardware and a 7B model on a CPU can take most of a minute on a long message. The card shows `pending`
throughout and the deterministic score is already on screen, so the wait costs latency on the AI section
rather than on the verdict.

## The cloud design, which is not built

Designed deliberately and left inert, and **not offered in the settings page** — the option appears only
for someone whose stored setting is already `cloud`, because a mode that returns no assessment on every
message reads as a broken AI section rather than an unfinished feature. The seam still exists —
`CloudAnalyzer` implements the same interface — so enabling it changes no analysis, scoring, or UI code.

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

- **No vendor credential in the extension, ever.** An API key shipped in an extension is a published API
  key. The backend holds it.
- **One egress point.** Only the service worker makes network requests, so there is exactly one function
  to audit. Its `fetch` uses `credentials: 'omit'` and `redirect: 'error'`, so it cannot follow a redirect
  to another origin or attach ambient cookies.
- **One redaction function.** `buildCloudPayload` (`src/analysis/llm/redact.ts`) decides what leaves, and
  `test/privacy.test.ts` asserts field by field what it keeps *and* what must not be present, so a field
  added carelessly later fails the suite.
- **Deterministic findings travel as ids**, not re-derived, so the backend never needs the data required
  to recompute them. This is also why the payload may carry `linkDomains` when the local prompt withholds
  them: they arrive next to the verdicts already reached about them, as context for a judgement rather
  than as material for a guess. A backend that instead asked its model "does this domain look right"
  would be reintroducing precisely the false alarm withholding them was meant to end.
- **HTTPS-only, validated.** `normalizeBackendUrl` accepts only an `https:` origin plus optional path
  prefix, so editing storage cannot point the adapter at `http://`, at a `javascript:` URL, or straight at
  a model vendor.
- **Opt in twice.** Cloud mode requires both an explicit mode choice and a URL, and neither has a default.
- **No fallback from local to cloud.** If the on-device model is missing, PhishLens does not quietly send
  mail to a server instead.
