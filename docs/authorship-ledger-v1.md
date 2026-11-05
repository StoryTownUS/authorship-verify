# Authorship record — format `authorship/v1` (Phase 0 spec)

Status: **FROZEN** (owner OK 2026-11-04). Core + vectors + CLI built (Phase 0). Once frozen, this is a long-lived contract: a v1 record must verify
forever. Changes after freeze = a new version (`authorship/v2`), never an edit to v1.

Read with: `proof-of-authorship.md` (the why), `~/StoryTown/handoffs/proof-of-authorship-build-2026-11-04.md` (plan).
Acceptance test = the FAQ (`src/app/landing/faq/content.ts`), word for word.

## 0. Owner decisions this spec builds on (2026-11-04)
| # | Decision |
|---|---|
| 1 | Seal when a work session ends (at most once a day) + at every export |
| 2 | Record every action that changes the work or asks the AI, with a category + one of 3 weights. Typing is grouped (one entry per save / pause), never per keystroke. No mouse, no keystrokes |
| 3 | Working-style fingerprint = computed on the user's own machine from the record (pace, reject rate, rewrite depth). Never a score. Not part of Phase 0; the record only has to keep timing |
| 4 | Signing = an automatic **device key** (browser-made, can't be copied out, no prompt). Passkeys later as an optional upgrade. Settings → Authorship warns honestly that wiping browser data deletes the key (old seals stay valid) and deletes any project that is not in the cloud or exported |
| 5 | Shows in: the Bell (notices), a per-project Authorship panel (history), Settings → Authorship (keys + warning) |
| 6 | Full record lives in the project (browser storage + cloud project + `.storytown` file). Server keeps only a fingerprint log (hashes + its own receive time + account) and co-signs seals as witness. No decision content on our server unless the user opted into research |
| 7 | Research (AI collaborator) = the SAME record, anonymized, only for users who opted in (Settings → Plan, already built). No second capture system |

## 1. FAQ promise → what in this format makes it true
| FAQ promise | Made true by |
|---|---|
| "private, tamper-evident record of your directing decisions" | §3 entries in a hash chain; content never in the entry, only salted fingerprints (§4) |
| "you seal that record with your own key, on your own device" | §6 seal signed by the device key (§7) |
| "A fingerprint … timestamped in Bitcoin's public record" | §6 seal head → OpenTimestamps (`.ots`, Phase 3) |
| "tied to real AI generations" | §3 `provider` + Studio Bridge receipt id |
| "never changed since" | §8 verifier: any changed byte fails loudly |
| "your project file holds … your signatures and your timestamp receipts" | §9 files inside the `.storytown` ZIP |
| "doesn't need us" / "open verification tool" | §8 verifier is pure code + Bitcoin headers; the witness signature is a bonus, never required |
| "same on every tier" | No plan gate anywhere. Not a setting |

## 2. Building blocks (fixed for v1)
- **Canonical JSON:** RFC 8785 (JCS). Library: `canonicalize` (npm, Apache-2.0, zero deps; checked 2026-11-04,
  v5.1.0). v1 forbids non-integer numbers anywhere (times are ISO strings), so number formatting can never differ.
- **Hash:** SHA-256, written `sha256:<64 lowercase hex>`. Library: `@noble/hashes` (audited; v2.4.0). Every hash
  carries its algorithm tag so a later version can add another.
- **Signatures:** ECDSA P-256 + SHA-256 (`ES256`), raw 64-byte `r‖s`, base64url. Same curve passkeys use, so
  passkeys plug in later with no new verifier code. Signing in the browser: WebCrypto, key created
  `extractable:false`. Verifying: `@noble/curves` p256 (audited; v2.4.0), so the CLI and the browser run the same code.
- **Key id:** `sha256:` of the JCS of the public JWK `{crv,kty,x,y}` (RFC 7638 thumbprint style).
- **Random:** `crypto.getRandomValues`. Salts are 16 bytes, base64url.
- **Text:** stored as UTF-8. Producers normalise user text to NFC before fingerprinting.
- **Exact bytes (forced by the tamper tests):** every JSONL line is byte-identical to its JCS form and ends with exactly
  one `\n` (the last line too); `keys.json` / `witness-keys.json` are one JCS line + `\n`; base64url is decoded
  strictly (only the one canonical encoding of the bytes is accepted). ECDSA signatures with high S are accepted
  (WebCrypto doesn't normalise S; signatures are never used as ids).

## 3. Entry
One line per entry in a JSONL file; **each line is exactly the JCS form of the entry** (the verifier rejects a line
that isn't).

```json
{"v":"authorship/v1","chain":"Hq3…","seq":12,"prev":"sha256:9f2c…",
 "type":"direct.kept","w":"choice","by":"you","at":"2026-11-04T18:22:01.123Z",
 "account":"sb:6c1e…","refs":[{"role":"shot","id":"shot_8f…","c":"sha256:41aa…"},
 {"role":"take","id":"take_02…","c":"sha256:07be…"}],
 "provider":null,"cause":null,"t":{"ms":8400,"rev":2}}
```

| Field | Required | Meaning |
|---|---|---|
| `v` | yes | Always `"authorship/v1"` |
| `chain` | yes | Chain id (16 random bytes, base64url). One chain per device per project (§5) |
| `seq` | yes | 0, 1, 2… no gaps |
| `prev` | yes | Entry hash of `seq-1`; `null` only at `seq` 0 |
| `type` | yes | `area.action` from the type list (§10). Unknown types are valid (counted as "other") |
| `w` | yes | Weight: `"big"` \| `"choice"` \| `"edit"` |
| `by` | yes | `"you"` (the user's own click) \| `"ad"` (the AD did it for the user). Honesty: the certificate counts both |
| `at` | yes | Device clock, ISO-8601 UTC with ms. **Not trusted**; only seals' Bitcoin anchors are |
| `account` | yes | `"sb:<supabase user id>"` or `null` when signed out |
| `refs` | yes | List (may be empty) of `{role, id?, c?}`: `id` = the app's own object id (random, reveals nothing); `c` = salted fingerprint of that object's content at that moment (§4). Never content |
| `provider` | yes | `null`, or for AI calls `{name, model, gen, bridge}`: maker + official model name (plain), `gen` = fingerprint of the maker's generation id, `bridge` = Studio Bridge receipt id from our server, or `null` |
| `cause` | yes | `null`, or `seq` of the entry that caused this one (an AD action → the user's message that asked for it) |
| `t` | yes | `null`, or timing `{ms, rev}`: ms from shown to decided, revision count (from Directing Signals) |

No other fields. A field added later = `authorship/v2`. The **entry hash** = `sha256(utf8(JCS(entry)))`.

## 4. Fingerprints of content (salted commitments)
`c = "sha256:" + hex(SHA-256( salt ‖ utf8(value) ))`
- `value` = the content's own hash string for media (`BinAsset.contentHash`, already SHA-256 of the bytes), or the
  NFC text for text (prompt, script version, Bible field).
- The salt is **not** in the entry. Salts live in `authorship/salts.jsonl` (`{"c":…,"salt":…,"kind":"hash"|"text"}`),
  which stays private. Showing someone the record without salts reveals only types, counts and times; revealing one
  piece of work = handing over that one salt + the content. This is how selective disclosure works later.
- Why salted: a short prompt like "a girl with blue hair" could otherwise be guessed by hashing guesses.

## 5. Chains: one per device per project
- A project's record = a set of chains. Each browser (device) writes its own chain for that project, starting with a
  `chain.start` entry that names its device key (§7) and, optionally in `refs`, the latest heads of the other chains it
  had seen (`role:"continues"`), which links the devices' histories.
- Two tabs in the same browser share one chain; writes are serialised with Web Locks (`navigator.locks`, name
  `authorship:<projectId>`) inside one IndexedDB transaction. No merge rule is ever needed.
- Cloud save merges by chain id: union of chains; for the same chain the longer one wins only if the shorter is its
  prefix. Two different versions of the same chain = **loud integrity problem in the Bell**, never a silent pick.

## 6. Seal
One line per seal in `authorship/seals.jsonl`. The **statement** is what gets signed:

```json
{"v":"authorship/v1","chain":"Hq3…","seal":3,"seq":212,"head":"sha256:…",
 "reason":"session_end","at":"2026-11-04T23:10:00.000Z","key":"sha256:<device key id>"}
```
The stored seal = `{"statement":{…},"sig":"<base64url ES256 over JCS(statement)>","witness":<§6b or null>,
"ots":[<§6c>]}`.
- `reason`: `"session_end"` | `"export"`. `seal` counts 0, 1, 2… per chain; `seq`/`head` = last entry covered.
- **6b Witness** (Phase 2): `{"key":"storytown-witness-<n>","received":"<server ISO time>","sig":"…"}`, the server's
  ES256 signature over `JCS({statement, received})`. Our witness public keys are published in the repo and inside
  every record (`authorship/witness-keys.json`) so it verifies offline. Bonus, never required.
- **6c Bitcoin** (Phase 3): `{"calendar":"<url>","file":"ots/<chain>-<seal>.ots","state":"pending"|"anchored",
  "block":<height or null>}`. At least 2 calendars. The stamped digest = the raw 32 bytes of `sha256(JCS(statement))`.
  `.ots` files are binary, beside the seals.
- A seal that can't get signed or stamped goes to the Bell (loud). "Sealed, anchoring later" is normal; pending more
  than 24 h becomes a Bell problem.

## 7. Keys
- **Device key** created on first use per browser: WebCrypto ECDSA P-256, `extractable:false`, kept in IndexedDB.
- Its public JWK goes in the record as a `key.added` entry (refs `[{role:"key", id:"<key id>"}]` plus the JWK in
  `authorship/keys.json`, keyed by key id). The `chain.start` entry is followed immediately by its `key.added`.
- Lost key (browser data wiped): a new chain + new key start; the record shows "new key added on <date>". Old seals
  verify forever with the old public key already in the file.
- `key.retired` entries end a key from that `seq` on; a seal by a retired key fails.
- Passkeys (later): same `ES256`, a new key `kind:"passkey"` in `keys.json` with the WebAuthn data needed to check the
  signature. No change to entries or seals.

## 8. Verifier (`src/lib/authorship/verify.ts`, same code in the CLI)
Pure function: `verify(files) → report`. Zero network calls. Checks, per chain, in order:
| Code | Fails when |
|---|---|
| `E_VERSION` | `v` isn't `authorship/v1` (newer → "update the verifier", never "invalid") |
| `E_JSON` / `E_NOT_CANONICAL` | a line isn't JSON, or isn't byte-identical to its JCS form |
| `E_FIELD` | a field is missing, extra, the wrong type, or a non-integer number |
| `E_SEQ` | `seq` not 0,1,2… or `chain` differs inside one chain |
| `E_PREV` | `prev` ≠ hash of the previous entry |
| `E_START` | chain doesn't begin with `chain.start` + `key.added` |
| `E_SEAL_HEAD` | a seal's `head` ≠ hash of entry `seq` |
| `E_KEY` | seal key not added before `seq`, or retired, or missing from `keys.json` |
| `E_SIG` | device or witness signature doesn't verify |
| `E_OTS` | an `.ots` proof doesn't commit to the seal digest (Phase 3) |
Every failure names the file, line and code. One changed byte anywhere → a failure, never a quiet pass.
Warnings (not failures): device time going backwards; entries after the last seal ("not sealed yet").
Report (plain words for the panel/verify page): record intact · N decisions · sessions sealed · signed by key(s) ·
witnessed · anchored in Bitcoin block N / waiting.
Bitcoin check needs block headers: the CLI takes them from the user's own node or any public block explorer the user
picks (never ours by default).

## 9. Files inside `.storytown` (ZIP; `STORYTOWN_VERSION` stays 4, files are additive)
```
authorship/
  chains/<chain>.jsonl     entries (§3)
  seals.jsonl              seals (§6)
  keys.json                public keys by key id (§7)
  witness-keys.json        Story Town witness public keys (§6b)
  salts.jsonl              PRIVATE salts (§4) — left out of any shared proof package
  ots/<chain>-<seal>.ots   Bitcoin receipts (§6c)
  receipts.jsonl           server fingerprint-log receipts {chain,seq,hash,received} (Phase 1; optional)
```
Old files without `authorship/` open fine (no record yet). In the browser the same data lives in IndexedDB per
project, and the cloud project save carries it.

## 10. Type list v1 (built from what the app already captures; no new capture system)
Searched: `directing-signals.ts` (SignalIntent), `decision-event.ts` (DecisionEventType), `project-store.ts` `_mutate`
(no action names today → Phase 1 tags each store action). Phase 1 wires both existing systems into this record.
| Type | w | Comes from today |
|---|---|---|
| `chain.start`, `key.added`, `key.retired` | big | new (record itself) |
| `write.script_saved` | big | screenplay save / version (typing grouped per save or 60 s pause) |
| `write.story_changed` (logline, treatment, beats) | edit | `beat_commit`, `treatment_commit` |
| `bible.changed` (character, location, prop, look) | edit | `character_edit`, `location_edit`, `style_change` |
| `visualize.shot_changed` (blocking, framing, lens, light) | edit | `framing_choice`, `movement_choice`, store actions |
| `ai.asked` (AD message, generation request) | choice | `use-ai-chat`, Studio Bridge |
| `ai.received` (a picture, video, voice, music back) | edit | Studio Bridge `metadata.sent` + receipt |
| `direct.kept` / `direct.rejected` / `direct.prompt_changed` / `direct.compared` / `direct.left_alone` | choice | SignalIntent accept / reject / override / comparison / defer |
| `direct.take_chosen` (final pick for a shot) | big | comparison signal |
| `edit.cut_changed` (Muybridge timeline) | edit | Muybridge store actions |
| `media.imported` (file brought in, not made here) | edit | Bin import — marked imported so the proof never claims it |
| `finish.exported` (hash of the exported file) | big | export |
| `intent.set` / `intent.cleared` | choice | `intent_set`, `intent_clear` |
Research use (opted-in only): an entry + the project's content at that moment rebuilds "what was offered, what was
picked or changed, how long it took" — the training example for the AI collaborator.

## 11. Phase 0 deliverables (exit = proved, not claimed)
1. `src/lib/authorship/` pure TS (no React, no stores): `types.ts`, `canonical.ts`, `hash.ts`, `commit.ts`,
   `chain.ts` (append/next entry), `seal.ts` (statement + sign with an injected signer), `verify.ts`, `MAP.md`.
2. Test vectors `src/lib/authorship/vectors/v1/`: RFC 8785 cases, entry→hash, commitment, a 5-entry chain, a seal
   signed with a fixed test key (ECDSA RFC 6979 deterministic → reproducible), and one tamper case per error code.
3. CLI `tools/authorship-verify/` running the same `verify.ts` on a `.storytown` file or an `authorship/` folder.
4. Exit: vitest green on the vectors; CLI verifies the sample; flipping any single byte of any file in the sample
   fails with the right code (a test loops over every byte of the sample chain).
5. `tsc --noEmit` clean. New deps: `canonicalize`, `@noble/hashes`, `@noble/curves` (all checked 2026-11-04).

## 12. Later phases need (not in Phase 0)
- OpenTimestamps: the official JS client (`opentimestamps` 0.4.9) was last published 2022 with dead dependencies
  (`request`, `bitcore-lib`) → write our own small client on `@noble/hashes` in Phase 3 (submit digest to ≥2
  calendars, store pending, upgrade, parse/verify the `.ots` ops).
- Witness key: its own key held by our server only, never a provider key, never logged.
- `flushSignals()` today sends every user's Directing Signals content to Supabase → Phase 1 changes it to
  fingerprints only, content copy only when opted into research (old test rows cleared; no real users yet).

### Note (Nov 5 2026, Phase 2 step 4) — witness keys
A checker trusts a witness only under a PUBLISHED Story Town key (`src/lib/authorship/witness.ts`; first key
`storytown-witness-1`, made Nov 5 2026). `witness-keys.json` inside a record is a convenience copy: if it holds a
different key under a published id → `E_SIG`; a witness under an id the checker doesn't know → warning
`W_UNKNOWN_WITNESS`, not counted. Witness keys use `kind:"device"` to stay inside the v1 key-file shape. The server
witnesses a seal only if the creator's signature verifies and the sealed decision is already in that account's
fingerprint log with the same fingerprint.

### Note (Nov 5 2026, Phase 2 step 5) — checking Bitcoin
The checker reads each seal's `.ots` offline: the file must be `ots/<chain>-<seal>.ots`, prove THIS seal's digest,
and the receipts must say exactly what the proof says (else `E_OTS`). A seal with ≥1 Bitcoin attestation counts as
anchored; the blocks go in `report.bitcoin`. Whether Bitcoin's block N really has that merkle root needs a block
source the checker chooses (never Story Town by default): until asked → `W_BLOCK_NOT_CHECKED`; a disagreeing source
→ `E_OTS`; an unreachable one → "couldn't check" (CLI exit 2), never a pass. Replaces `W_OTS_NOT_CHECKED`.

### Note (Nov 5 2026, Phase 3 step 1) — the claim and revealed decisions (add-only, v1 unchanged)
- **The claim** (FAQ: "signing it means putting your own name on the claim, permanently") is an ordinary decision:
  type `finish.claimed`, w `big`, one ref `{role:"claim", c}` where c = `commit('text', JCS({name, title}))`. It is
  then sealed (reason `export`: a claim is made when a proof package is made), so the device key signs it, Story Town
  witnesses it and Bitcoin dates it exactly like any seal. No new seal reason, no new field: old checkers accept it
  (type names are open, §10 regex).
- **`revealed.jsonl`** (optional file, only in shared proof packages): one canonical line per revealed decision ref
  `{chain, kind, ref, salt, seq, value}`. A checker requires: the entry exists, `refs[ref].c` exists, and
  `commit(kind, value, salt) === c`; otherwise `E_REVEAL`. A revealed ref not covered by any seal gets
  `W_REVEAL_UNSEALED` (it is shown, but nothing vouches for its date). This is also the "reveal one decision" tool.
- The checker reports a claim as **claimed and signed by the creator** ("Directed by <name>"), never as proven
  identity: the name is whatever the creator's account said; the record proves when it was signed and that it
  never changed. A record may hold several claims (renamed film); the latest sealed one is the current claim.
- Shared proof packages never contain `salts.jsonl` (spec §9): only the salts the creator chose to reveal travel,
  inside `revealed.jsonl`.
