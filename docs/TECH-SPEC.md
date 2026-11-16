# ReaOverflow — Technical Specification & Implementation Plan

> **Status:** Draft v0.1 (2026-11-14). Counter-REA software protection for C#/.NET, designed from scratch.
> **Audience:** implementers. **Scope:** defensive IP protection for assemblies *you own*.

---

## ⚠️ Empirical correction (2026-11-15) — read before the model sections

This document was written from a **source audit** of REA and specifies a white-box **model**
(`ReaModel`) of REA's budget. That model has since been **validated against the real `rea` CLI**
(`rea@6.7.0`/`6.9.0`) on FileHound (a real WPF app, 3 managed DLLs), and the model **over-predicts**.
The measured reality, which overrides the modelled claims below wherever they conflict:

- **No budget exhaustion.** REA's `inspect-managed-members` decoded **both** original and protected
  assemblies **completely** (~8–10 MB representation, **under** the 64 MiB cap). REA uses **plain byte
  accounting** of its representation, **not** the 256×/row, 256×/instruction, 256×/blob-byte, 512/type
  multipliers §1.1 assumes. So `analyze`'s `crossesBudget:true` is a **modelled, optimistic** verdict,
  **not** an observed outcome.
- **Measured effect = a ~20–23% representation-token tax + decoys**, from **P2** (call-edges +21%) and
  **P3** (field-accesses +34%), plus **P4** decoy archetypes (v2 measured 24 surfaced across the
  3-DLL app from the then-8 security archetypes; the set is now **10** — three functional subsystems
  added, re-measurement pending). A real cost, not a denial — and the decoys' real value is
  goal-dependent misdirection (§4), not token share.
- **`#JTD` is a no-op** against REA (it parses straight through; `inspect-managed-members` **and**
  `inspect-managed-artifact` succeed with 0 errors). The **deep-nesting cap** (depth 70) also does
  **not** bite. Only the **array-rank cap** (33 > 32) lands (`unsupported-signature`, 1 member partial).
- **P7 self-seal** is **tamper-evidence, not anti-analysis** — REA ignores the appended hash.

Treat §1.1's multipliers, §2's "size thesis", §6's `ReaModel`, and every "hard stop" / "budget
exhausted" statement below as **modelled design intent, labelled DesignedFor** — not measured REA
behaviour. For ground truth run the **empirical gate** (`scripts/rea-token-gate.ps1` / `.sh`), which
drives the real `rea` CLI and asserts the measured token ratio. Full evidence:
`M:\Projects\rea-comparison\` (REPORT.md, dashboard.html, evidence/).

---

## 0. Disclaimer & ethical scope (read first)

ReaOverflow is a **defensive software-protection** tool, built in the same spirit as BLA
(`qybaihe/bla`) and the commercial .NET obfuscator space (ConfuserEx, Dotfuscator, Eziriz).
It is intended **only** for authors and security teams hardening **their own** .NET
intellectual property against automated AI reverse-engineering agents (notably
`morluto/rea`) and LLM-driven analysis/cloning pipelines.

It is **not** a malware packer and must not be used to hide malicious code, evade
security/AV/EDR products, or protect software you do not own. Every claim in this project
is held to an **honesty contract** (borrowed from BLA's own self-discipline): features are
labelled **verified** (empirically tested here) or **designed-for** (modelled, not yet
proven), modelled cost numbers are labelled as *estimates*, and runtime-equivalence is only
claimed where we actually executed and compared the protected assembly.

---

## 1. Threat model: what REA actually does to .NET

From source-level audit of `morluto/rea` (`src/dotnet/`, 57 files) and `qybaihe/bla`:

- REA's .NET analyzer is a **bespoke, read-only, execution-free** PE + ECMA-335 metadata +
  CIL parser written in TypeScript. **It never loads/executes the assembly, never resolves
  deps through a CLR, and does not decompile to C#** (ILSpy is optional, dev-only, and its
  output is labelled "inference", not canonical).
- It extracts: PE/CLI headers, metadata streams + **table row counts**, module/assembly
  identity + MVID, types/fields/methods, field `Constant` defaults, **decoded CIL**
  (opcodes, `il_sha256`, `normalized_il_sha256`, call edges, field accesses), `#US` user
  strings, P/Invoke boundaries, custom attributes, target frameworks.
- **It does NOT deobfuscate.** No de4dot, no ConfuserEx handling, no string decryption, no
  control-flow deflattening. Renamed/Unicode identifiers are returned verbatim; encrypted
  strings stay opaque; flattened control flow is decoded as-is, not reconstructed.
- It is **crash-resistant** by design (explicit continuation stacks, bounded reads, typed
  per-item failures). DoS-by-crash is unlikely; the intended ceilings are a **byte budget**
  plus a few **fixed structural caps**.

### 1.1 REA's exact ceilings (our attack surface)

| Lever | Source | Value / formula | Effect when tripped |
|---|---|---|---|
| Snapshot cap | `managedInspectionLimits.ts` | `DEFAULT_MANAGED_SNAPSHOT_BYTES = 128 MiB` | whole-read refusal |
| **Representation budget** | `managedInspectionLimits.ts` / `ManagedDecodeBudget.ts` | `DEFAULT_MANAGED_REPRESENTATION_BYTES = 64 MiB` (single pool for metadata + CIL + final JSON) | `resource-limit` → coverage `partial`/`unavailable` |
| Per metadata row | `ManagedDecodeBudget.ts:52` | **256 B/row** | — |
| Per `#US`/string | `ManagedDecodeBudget.ts:82` | **`len×6 + 2`** | — |
| Per CIL instruction | `ManagedMethodBodyReader.ts:165` | **256 B** (+256 if token operand) | — |
| Per signature/LocalVarSig blob | `...Core.ts:837,922` | **`blobLen × 256`** | — |
| Per type | `ManagedMemberInspector.ts:236` | 512 B | — |
| Final JSON projection | `ManagedDecodeBudget.ts:154` | exact JSON byte length, same 64 MiB pool | compounding |
| **Type nesting depth** | `ManagedSignatureTypeNames.ts:29` | **`MAX_TYPE_NESTING_DEPTH = 64`** | name unresolved, `name_sha256 = null` → breaks naming & cross-build compare |
| **Array rank** | `...Core.ts:439` | **`MAX_ARRAY_RANK = 32`** | `unsupported-signature`, member partial |
| LocalVarSig local count | `...Core.ts:842` | must be `1..65534` | malformed |
| Unknown opcode / short operand | `ManagedMemberInstructionDecoder.ts:468` | stops decode at first | body `partial`/`malformed` |
| **`#JTD` stream** (minimal-EnC marker) | `ManagedMetadataLayout.ts:471` | source says presence → `unsupported-metadata` | ⚠️ **MEASURED NO-OP** — REA parses through it with 0 errors; never flagged |

> ⚠️ These ceilings are from a **source audit**; see the empirical correction at the top. Measured
> against `rea@6.7.0`/`6.9.0`: the **multipliers do not apply** (REA uses plain byte accounting),
> **`#JTD` is a no-op**, and the **nesting cap does not bite**. Only the **array-rank cap** landed.

**Honesty caveat:** the 64 MiB budget is user-overridable (`--max-metadata-representation-bytes`).
A genuine budget crossing would therefore only **delay/degrade**, not block — but in testing REA
**did not cross it at all** (it decoded protected assemblies completely). Treat the "automated agent
runs out of budget on defaults" story as **modelled intent that did not reproduce**. What *did* hold:
REA's principle that *"omitted facts never become empty observations"* means the **decoys** (P4) are
the durable misdirection — the agent cites them as real. `#JTD` and the nesting cap are **not**
genuine hard stops against REA (measured); the array-rank cap is the one structural lever that bites.

### 1.2 What defeats the *LLM*, not just the parser

From arxiv 2505.19887 (LLM assembly deobfuscation, 4-D framework):
**combined techniques = "universal failure"**; **instruction/constant substitution** is
*highly resistant*; control-flow flattening *moderate*; **bogus control flow alone is weak**
(LLMs detect it). LLMs are worst at distinguishing redundant vs. real control flow and at
reproducing arithmetic transforms. → **Layering is mandatory; never ship a single pass.**

---

## 2. The size thesis — "same effect, small file"

This was the central engineering thesis, drawn from §1.1's source audit: **REA's charges are
(modelled as) wildly disproportionate to disk bytes**, so a **few hundred KB** of structured
metadata/IL would induce a ≥64 MiB charge without bloating the file.

> ⚠️ **This thesis did not reproduce against the real REA tool** (see the empirical correction at the
> top). `rea@6.7.0`/`6.9.0` uses **plain byte accounting**, not the per-item multipliers below, and
> decoded protected assemblies completely. The passes built on this thesis (notably P5) still impose
> a real but **modest** cost — a ~20–23% token tax — via volume of real metadata, not a ≥64 MiB
> crossing. Keep the thesis as **design rationale**, but do not claim budget exhaustion.

- A single `LocalVarSig` blob charges **256× its length** → ~256 KB of budget per 1 KB on disk.
- `#US` strings charge **6×**; CIL instructions **256 B each** regardless of their 1–5 B encoding.
- Type-nesting depth 64 and the `#JTD` stream cost **a handful of bytes** for cap/hard-stop effects.

**Rule:** prefer transforms whose *analysis cost* is superlinear to their *disk cost*. Rank
passes by **(REA-charge + LLM-resistance) / disk-bytes**. Explicitly **avoid** the size-heavy
classics: full method virtualization/VM packing, bulk method-body duplication, and embedding
large decoy blobs. A per-run **size budget** (default: ≤ +25% or +512 KB, whichever larger)
is enforced by the pipeline; passes that would exceed it are scaled back.

---

## 3. Architecture

```
reaoverflow (CLI)
 ├─ Core
 │   ├─ AssemblySubstrate   (dnlib load/save; the managed R/W layer)
 │   ├─ RawPeRewriter       (FROM SCRATCH: metadata-root / stream post-processor)
 │   ├─ SeededPrng          (xorshift128+/mulberry32; per-project seed in .reaoverflow)
 │   └─ SizeBudget          (tracks disk delta, vetoes bloat)
 ├─ Passes  (each: Plan → Apply → cost-estimate → runtime-safety class)
 │   ├─ P1 StringEncryption        P2 OpaquePredicates/DeadBranch
 │   ├─ P3 MbaConstantSubstitution P4 DecoyInjection (our CLR archetypes)
 │   ├─ P5 MetadataInflation       P6 RawMetadataParserBreaks (gated)
 │   ├─ P7 SelfSeal/Entangle       P8 RuntimeDecoyTelemetry (decorative)
 │   └─ P9 RepresentationBomb (gated; quadratic cross-ref → measured rea exhaustion)
 ├─ ReaModel  (budget simulator: exact §1.1 formulas + caps → predicts status)
 ├─ Verify    (runtime-equivalence · ilspycmd degradation · budget assertion · honesty report)
 └─ Cli       (protect · analyze · verify; intensity levels; config)
```

### 3.1 Substrate decision (important — resolves "from scratch")

"From scratch" = **we design all protection logic ourselves and copy no obfuscator and no
BLA decoy data.** It does **not** mean re-implementing a full ECMA-335 reader/writer by hand
(months of work, and a buggy writer produces unloadable assemblies). We stand on a
**low-level metadata library as the read/write substrate** — the same foundation ConfuserEx
and dnSpy are built on:

- **`dnlib`** (MIT, by 0xd4d/dnSpyEx authors) for managed-level surgery: IL injection,
  decoy types/methods, string encryption, metadata-table inflation, type-nesting. dnlib can
  also *deliberately emit invalid metadata* (the mechanism ConfuserEx's anti-tamper uses),
  which we need.
- **Our own `RawPeRewriter`** (genuinely from scratch) for the sub-dnlib byte tricks that
  live in the metadata-root/stream layer: `#JTD`, duplicate/mixed-case/padded stream names,
  tables-header ExtraData, data-directory hiding. This is a small, focused ECMA-335
  metadata-root patcher we write and own.

This split is the honest reading of the request and the only sane engineering path. *(Open
to override — see decisions at end.)*

---

## 4. Transform passes

Each pass declares: **mechanism**, **REA effect**, **LLM effect**, **disk cost**,
**runtime-safety class** (`safe` = proven loadable+equivalent; `gated` = must pass runtime
tests per-target; `decorative` = no security claim), and **default intensity**.

### P1 — String encryption + lazy decryptor  `[safe]`
- **Mechanism:** replace `ldstr "literal"` with `call Decrypt(int id)`; store ciphertext in a
  blob/`#US`; decryptor is a small injected method (XOR/AES-CTR keystream from per-project seed).
- **REA effect:** `#US`/string facts become opaque ciphertext; REA never runs the decryptor,
  so plaintext is unrecoverable statically. Long ciphertext also feeds the 6× string charge.
- **LLM effect:** removes the single richest signal LLMs use (readable strings/identifiers).
- **Disk:** ~ciphertext ≈ plaintext size + small decryptor. **Cheap.**

### P2 — Opaque predicates + dead-branch decoy graph  `[safe]`
- **Mechanism:** inject `if (opaqueFalse(seed)) { <decoy IL> }` guarding dead blocks. Opaque
  predicates re-expressed in CIL: quadratic non-residue (`7x²−1 ≠ y² mod 7`), affine MBA over
  `Z_2³²` (`mInv·(m·(x^k)+2m·(x&k)+c)+d == x+k`), signed/unsigned bit-31. Runtime takes the
  real path only (**O(1)**); static analysis must enumerate the dead graph.
- **REA effect:** inflates instruction count (256 B each) + call edges REA must record.
- **LLM effect:** moderate alone — **must combine** (see §1.2). Decoy blocks also carry P4 bait.
- **Disk:** few IL bytes/predicate. **Cheap.**

### P3 — MBA / constant substitution  `[safe]`  ← strongest anti-LLM
- **Mechanism:** rewrite *real* constants and arithmetic into mixed boolean-arithmetic
  identities (`x+y → (x^y)+2·(x&y)`, constant → sum of opaque terms), so the true values never
  appear as literals.
- **REA effect:** field `Constant` defaults & inline literals stop being ground truth.
- **LLM effect:** **highly resistant** per arxiv — models reproduce wrong constants/ops.
- **Disk:** small per site. **Cheap.** (Applied to selected hot/sensitive methods, not all.)

### P4 — Decoy injection (OUR CLR archetypes, not BLA's)  `[safe]`  ← the measured misdirection win
- **Mechanism:** generate plausible-but-false C#/CLR logic, seeded & per-project unique. **Densely
  interconnected (2026-11-15):** ten archetypes (seven security + three functional, non-security)
  + a central `SubsystemBroker` hub, wired with
  decoy→decoy call edges, typed cross-type fields, and a bounded set of **real→decoy** call edges —
  a handful of the user's own methods gain an opaque-false-guarded, never-executed call into the
  broker (P2's proven always-true guard; state machines skipped), so the decoys look *used by real
  code*. Each decoy is inert (never reached at runtime), so behaviour is unchanged.
- **MEASURED (two targets):** on the small sample, densifying the decoys raised the real-REA token
  ratio from **1.62× → 2.03×** — but that is a small-sample artifact. On real FileHound (3 DLLs,
  `rea@6.9.0`, v2 re-run 2026-11-16) densification added only **+0.71%** tokens; decoys are a tiny
  token share of real code. The durable win is **misdirection surface + goal-dependence**: surfaced
  decoy types grew 5 → **24** (8 archetypes × 3 DLLs, 7 namespaces, `SubsystemBroker` hub), and a
  *security/licensing-audit*-framed agent was fully derailed (7 fake subsystems inspected, 0 real
  types, no conclusion) while a *purpose*-framed agent ignored every decoy (≈0% tax). Both sides
  still decode completely; REA records the cross-edges/fields as real wiring.
- **Our archetypes** (designed here; see §5): fake license/activation ring, feature-gate /
  tier matrix, P/Invoke "hardware dongle" shim, update/telemetry handshake, key-derivation stub.
- **REA effect:** decoys are clean, fully-`observed` facts; the real logic sits under
  `partial`/`unknown` coverage → agent cites decoys as primary and reconstructs the wrong system.
- **LLM effect:** supplies a coherent false narrative — the "poison".
- **Disk:** metadata rows (256 B REA-charge each) + small bodies. **Moderate; size-budgeted.**

### P5 — Metadata inflation (amplification engine)  `[safe]`
- **Mechanism:** the §2 thesis made concrete — a few large `LocalVarSig`/signature blobs, a
  controlled set of `#US` strings, and one **rank-33 array local** (rank >32 → `unsupported-signature`,
  the one structural cap-attack measured to bite REA, handover rea@6.9.0).
- ⚠️ **The deep-nesting cap-attack was CUT (2026-11-16):** measured against rea@6.7.0 it was a no-op
  at every depth tried (70 … 520 → 0 null names, coverage `complete`), and rea@6.9.0 ignored it too.
  REA resolves arbitrarily deep `SZArray` nesting, so the lever is retired.
- **MEASURED REA effect:** a modest token tax from real metadata volume, **not** `resource-limit` /
  budget exhaustion — the modelled ≥64 MiB charge does not reproduce (see the empirical correction).
- **Disk:** **very cheap**. Hard size cap applies.

### P6 — Raw metadata parser-break (duplicate stream)  `[gated]`
- **Mechanism (`RawMetadataPass`):** emits **two metadata streams with the same name** (a duplicate
  stream), via dnlib `MetadataOptions.CustomHeaps`. A strict ECMA-335 reader rejects a duplicate
  stream at layout parse; the CLR and dnlib keep the first stream of a name and ignore the rest.
- ✅ **MEASURED ANALYSIS-DENIAL vs real rea (rea@6.7.0 and 6.9.0, 2026-11-16 fuzz campaign).** rea throws
  `"Duplicate metadata stream"` at layout parse, so `inspect-managed-members`,
  `inspect-managed-artifact`, **and** `inspect-managed-native-boundaries` all report
  `metadata.status = malformed` / `coverage = unavailable` with **zero types/methods/fields/
  signatures/string literals** — rea's whole managed inventory is denied. The .NET 8 CLR + dnlib load
  and run the assembly **identically** (proven by the runtime-equivalence tests and
  `StructuralValidator`). `ReaModel` surfaces this as a **measured** `ReaMetadataDenied` fact (distinct
  from the modelled budget/caps); re-check with `scripts/rea-p6-denial-gate.ps1` / `.sh`.
- ⚠️ **Denial, not a crash.** rea **exits 0** and labels the file malformed — it does not segfault or
  exit non-zero. The win is that rea yields no managed members where the app runs fine. A true
  non-zero-exit crash was **not** reachable with load-safe input: rea's reader catches every layout
  `ManagedReaderFailure` and degrades gracefully; the only crash vectors need non-loadable metadata
  (every post-write byte-patch tried broke CLR load) or infeasibly large metadata. Equivalent measured
  constructions with the same denial, **selectable via `--p6-variant`**: `dup` (duplicate stream,
  default), `manystreams` (**>64 metadata streams**; the CLR has no cap), `badname` (**stream name
  with a non-printable byte**). All three are MEASURED (rea 6.7.0 and 6.9.0), load-safe, and covered
  by the `P6_RawMetadata_EachVariant_*` theory. The older `#JTD` marker was a measured **no-op** and
  is no longer used.
  A blind-fuzz sweep (random metadata byte-flips kept only when the mutant still loads on the .NET 8
  CLR and runs identically, oracled against rea 6.9.0) found **0 crashes / 0 hangs** across the
  load-safe mutants — only graceful `partial`/`complete` coverage — corroborating that a non-zero-exit
  crash is not reachable with load-safe input; only the targeted structural constructions reach DENIED.
- **Runtime safety:** duplicate streams are non-standard and can break other runtimes/strict loaders —
  ships **off by default**; runtime-test per target.
- **Disk:** **~constant bytes.**

### P7 — Self-seal / entangle (anti-tamper)  `[gated]`
- **Mechanism:** a `[ModuleInitializer]` (net5+) or injected `<Module>.cctor` recomputes
  SHA-256 over the module using a **canonical self-digest** (embedded 32-byte placeholder
  zeroed before hashing, finalised post-write) and optional sibling/sidecar digests. Mismatch
  → soft-fold (corrupt a derived constant) or hard-fail. Keeps attackers from nop-stripping
  decoys/predicates. Multi-site, combined `h0 ^ h1`.
- **Runtime safety:** gated — interacts with strong-naming/Authenticode (which we'd break), so
  signing is out-of-scope by default and documented. Must pass equivalence tests.

### P8 — Runtime decoy telemetry  `[decorative]`
- **Mechanism:** `Debugger.IsAttached` / `CheckRemoteDebuggerPresent` → surface believable
  decoy state. **Explicitly non-authorizing and decorative** (BLA's honesty rule): it does not
  block debuggers or gate licensing; it only feeds a live analyst misleading state.

### P9 — Representation bomb (quadratic cross-reference)  `[gated]`
- **Mechanism:** plant N dead static fields + N dead static methods across a few decoy types; every
  injected method body reads **all** N fields (`ldsfld`) and calls **all** N methods (`call`) →
  **2·N² cross-reference edges**. rea materialises those edges into its managed representation and
  crosses its **67,108,864-byte (64 MiB) representation budget**, returning
  `coverage.state = "unavailable"` with a `resource-limit` issue and **zero managed members** —
  a denial **by exhaustion**, distinct from P6's parser-break (`malformed`). rea exits 0 (~2.8 s),
  not a crash.
- **MEASURED** (rea@6.7.0, 2026-11-16): cliff ≈ 218k–238k edges on FileHound.Core.dll (N=330 →
  `complete` +870% tax; N=345 → `unavailable`). Defaults clear it with margin (Stealth 384 /
  Balanced 512 / Maximum 768).
- **Runtime-safe:** every injected method is unreachable (never JITed); methods sharing a per-build
  body *shape* are byte-identical so dnlib shares one RVA per shape → on-disk growth is ~O(k·N) (tens of
  KB) while rea's expansion is O(N²). The CLR loads and runs the assembly identically (runtime-equivalence
  + `P9HardeningTests`).
- **Open-source hardening — the per-build SEED is the secret (Kerckhoffs), not the algorithm.** Every
  fixed strip signature is randomized per build off the project seed (CLI default is a cryptographically
  random value — `SeedPolicy`; `--seed` for reproducible builds): compound, counter-free decoy names
  from wide pools across 2–4 namespace roots; uneven per-type member counts (no uniform cluster); k=3–6
  per-build body *shapes* (varied order/interleave/junk — breaks the identical-body clone tell while
  still sharing one RVA per shape); and decoy→real cross-boundary reads (`ldsfld`/`ldftn`) so the clique
  is not cleanly disconnected. On rea 6.9.0 the leaked type names read as a believable subsystem.
- **Reachability anchor:** a bounded, seeded set of real user methods gains an opaque-false-guarded dead
  `call` into the decoy clique (reuses P2/P4's pattern), so an ILLink-style reachability mark-sweep can't
  prune it as a zero-in-edge dead SCC. Guard always true → never executed → runtime unchanged.
- **Honest limit:** the hardening defeats signature/statistical strippers (Tier A) and a cheap
  reachability sweep (Tier B); it does **not** defeat a trace-based or constant-folding stripper (Tier C),
  which would need genuinely-running side-effecting decoys (declined, to keep runtime identical). Economic
  deterrent — buys cost/time, not impossibility.
- **Clean cross-version refusal:** P9's budget lever surfaces as `unavailable`/0-types on rea 6.7.0 but
  `partial`/names-only/0-methods on 6.9.0. To force a clean `malformed`/0-types refusal on **both**,
  stack P6: `--passes …,P6,P9` — P6's parser-break reports malformed with 0 types on 6.7.0 and 6.9.0
  (measured), while P9 guarantees exhaustion even if the budget is raised. Defense in depth.
- **Gated:** rea's 64 MiB budget is a per-command, user-raisable ceiling; off by default, re-check with
  `scripts/rea-p9-exhaustion-gate.ps1` / `.sh`.

---

## 5. Our decoy map (designed from scratch — not BLA's)

BLA's decoys are enclave/TPM2/Electron-IPC/AWS-token themed and JS-shaped. **We share none of
that content.** Our archetypes are CLR-native and generated from a per-project seed so no two
protected builds collide:

1. **`LicenseRing`** — fake RSA/ECDSA activation check (`RSACryptoServiceProvider`-shaped),
   inverted invariant (`valid = (sigParity == -1)` → always false).
2. **`FeatureTierMatrix`** — decoy entitlement/feature-gate table keyed off a fake config hash.
3. **`NativeDongleShim`** — fake `[DllImport("hasp_rt.dll")]`/`[DllImport("sentinel.dll")]`
   P/Invoke ring (names generated; DLLs never exist; branch never taken) → poisons REA's
   native-boundary inventory.
4. **`UpdateHandshake`** — decoy HTTPS update/telemetry state machine with plausible but dead
   endpoints (synthetic, non-routable; never contacted).
5. **`KdfVault`** — fake key-derivation (`Rfc2898DeriveBytes`-shaped) feeding an unused constant.

**Functional (non-security) archetypes — added post-v2, `DesignedFor` (not yet re-measured).**
v2 showed a *purpose*-framed agent dismisses an all-security decoy cluster, so these broaden
analyst-goal coverage beyond the licensing/DRM framing:
6. **`SerializationRegistry`** — fake wire codec (`msgpack`/varint/schema-rev) → bites a "how is
   data parsed/stored?" goal.
7. **`ProtocolRouter`** — fake network opcode router (`OP_HELLO`/seq-window/keepalive) → bites a
   "find the network protocol/C2" goal.
8. **`CacheCoordinator`** — fake LRU/WAL cache (`lru.evict`/`shard`/`fsync`) → bites a "find
   storage/DB" goal.

Each archetype: unique seeded symbol names, realistic attributes, an inverted invariant, and
emission **only inside P2 opaque-false guards**. Content templates live in
`Core/Decoys/*.cs` and are ours.

---

## 6. REA budget simulator (`ReaModel`)

We implement a **white-box model of `ManagedDecodeBudget`** from the formulas in §1.1, and measure
our output against it. `reaoverflow analyze <asm>` reports: modelled total charge, predicted
`coverage.state`, which caps trip, and the decoy/real ratio. This is **a model, labelled as such** —
the honest analogue of BLA's `token-estimator`.

> ⚠️ **The model over-predicts** (empirical correction at top). Every `analyze`/`verify` surface now
> carries a `measuredAgainstRea:false` flag and a disclaimer, and the JSON verdicts are renamed
> `modelledCrossesBudget` / `modelledAnyHardStop` / `modelledPredictedStatus` so no consumer reads
> them as measurement. **Ground truth is no longer out of scope:** `scripts/rea-token-gate.ps1` /
> `.sh` drive the real `rea` CLI (`rea inspect-managed-members <in|out> --token-count`) and assert the
> measured protected/original token ratio (default `>= 1.15x`). It is opt-in (needs Node + `rea`),
> not part of `dotnet test`.

---

## 7. Validation strategy ("test and validate… debug and test again until clear")

Three independent gates, all run by `reaoverflow verify` and in CI:

1. **Runtime equivalence (the hard gate).** For every pass and every sample target: build →
   run **original**, capture stdout/exit; build → **protected**, run, capture; assert
   identical. A pass that fails equivalence on a target is **disabled for that target** and
   reported — never silently shipped. (TDD: equivalence tests are written first.)
2. **Decompiler degradation (real tool).** Install `ilspycmd` (ICSharpCode.Decompiler, the
   same engine REA optionally uses). Decompile original vs protected; assert measurable
   degradation (decompile error, or garbage/`goto`-spaghetti, or missing plaintext strings).
   This is our **verified** anti-analysis evidence.
3. **Budget assertion (model — DesignedFor).** `ReaModel` must predict ≥64 MiB charge **or** a
   tripped cap, at the configured intensity, within the size budget. ⚠️ This gate checks the
   **modelled** design target, **not** measured REA resistance (the model over-predicts — see top).
   The **measured** counterpart is the opt-in empirical gate `scripts/rea-token-gate.*` (§6).

**Honesty report** (`verify` output): per-pass verified/designed-for, size delta, modelled
charge, equivalence result, ilspycmd result, and all known gaps (signing broken, P6/P7 gated).

---

## 8. CLI, config, determinism

```
reaoverflow protect <in.dll> -o <out.dll> [--intensity stealth|balanced|maximum]
                             [--seed <hex>] [--passes P1,P2,...] [--max-growth 25%]
reaoverflow analyze <asm>    # ReaModel report on any assembly (protected or not)
reaoverflow verify  <orig> <prot> [--run <cmd>]   # 3-gate validation + honesty report
```
Config `.reaoverflow` (JSON) persists the per-project seed and pass selection so decoy
identifiers are stable across builds but unique per project. `SeededPrng` drives all
randomness; no `DateTime.Now`/`Random` in generators.

---

## 9. MVP scope (this session) vs roadmap

**MVP (build + validate now):** project scaffold + solution; dnlib substrate load/save
round-trip (identity transform proven equivalent first); `SeededPrng`; `SizeBudget`;
**P1, P2, P4, P5** end-to-end on a sample console app; `ReaModel` budget simulator; `verify`
gates 1 (runtime equiv) + 3 (budget) wired; a sample target + xUnit tests; CLI `protect`.

**Fast-follow:** P3 (MBA), gate 2 (ilspycmd), honesty report polish.
**Gated/experimental:** P6 (RawPeRewriter tricks, validated one-by-one), P7 (self-seal), P8.
**Later/roadmap:** control-flow flattening pass, strong-name re-sign support, MCP server
surface (parity with BLA's agent integration), more sample targets (WPF, ASP.NET).

A full commercial-grade protector is a multi-month effort; this session delivers a **real,
buildable, runtime-equivalence-tested core** with honest per-feature status, not a finished
product.

## 10. Build milestones (TDD)

- **M0** Scaffold: `src/ReaOverflow.Core`, `ReaOverflow.Cli`, `tests/ReaOverflow.Tests`,
  `samples/HelloTarget`; git init. Identity round-trip test green.
- **M1** SeededPrng + SizeBudget (unit tests).
- **M2** P1 string encryption; runtime-equivalence test on sample green; strings gone from ilspy/strings.
- **M3** P2 opaque/dead-branch; equivalence green; instruction-count up.
- **M4** P5 metadata inflation + `ReaModel`; `analyze` shows ≥64 MiB within size budget.
- **M5** P4 decoys; equivalence green; decoy/real ratio reported.
- **M6** `verify` 3-gate + honesty report; CLI `protect/analyze/verify`; full suite green.

## 11. Honest risks & limitations

- **The model over-predicts (measured).** `ReaModel`/`analyze` claim `crossesBudget:true` for
  assemblies the real `rea` decodes **completely**; treat every modelled verdict as DesignedFor, not
  measurement. Measured effect = a ~20–23% token tax + decoys. Budget is overridable anyway, so even
  a genuine crossing degrades rather than blocks. Ground truth: `scripts/rea-token-gate.*` (§6).
- **P6 (duplicate stream) MEASURABLY denies rea's managed inventory** (malformed, 0 members on
  rea@6.7.0) while the app still loads+runs — but it is a **denial, not a crash** (rea exits 0 and
  labels the file malformed), measured on both rea 6.7.0 and 6.9.0. The older `#JTD`
  marker was a no-op. **P7 is tamper-evidence, not anti-analysis.** Do not market P6 as a non-zero-exit
  break or as REA-proof. P6/P7 can break loading or signing; strictly gated behind per-target runtime
  tests. Ground truth for P6: `scripts/rea-p6-denial-gate.*`.
- No protection stops a skilled human with dnSpyEx + time; goal is to make *automated/LLM*
  analysis unreliable and expensive, and raise the human cost — consistent with the field.
