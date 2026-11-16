# rea-representation-bomb

**A cheap, runtime-neutral .NET transform that makes an assembly expensive for an automated analyzer to understand — without changing a single byte of how it runs.**

![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4.svg)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24294281.svg)](https://doi.org/10.5281/zenodo.24294281)

`rea-representation-bomb` is the open, source-only reference implementation of the **representation
bomb** — a metadata transform for managed .NET assemblies that plants a *quadratic* set of dead
cross-references into an assembly. A static, LLM-driven reverse-engineering analyzer that tries to
materialize those references in memory is driven past a fixed budget and gives up with **zero
recovered members**; the .NET CLR, which never builds that graph, loads and runs the assembly
**byte-for-byte identically**. The cost is paid only by a tool that tries to understand the code, not
by the code itself.

It is built on [dnlib](https://github.com/0xd4d/dnlib), targets .NET 8+, and accompanies a research
preprint (citation below).

> **Scope.** This is a *defensive* protector for software **you own or are authorized to protect**.
> It is not a malware packer and does no AV evasion — it never disables antivirus and never hides a
> running payload from a scanner. It is an *economic deterrent* that raises an automated analyst's
> cost and time; it is not an impossibility proof. See [Limitations](#limitations--honest-scope).

---

## What it does, and why

Automated and LLM-driven reverse-engineering tools work by reading an assembly's metadata and CIL and
building an in-memory *representation* of everything they find — types, methods, fields, call edges,
field accesses. That representation has a budget. The representation bomb's bet is simple: **make an
honest, structurally valid assembly whose cross-reference graph is cheap to store on disk but
quadratically expensive to materialize in memory.** Past the analyzer's ceiling it stops decoding and
returns a resource-limit result, surfacing nothing — while the program itself is untouched.

This is a measured, economic lever, not a silver bullet. It targets *cheap automated analysis* (the
kind that scales to thousands of binaries, and the kind an LLM agent drives). A tool that actually
*executes or traces* the program can still strip never-executed code — see
[Limitations](#limitations--honest-scope).

## How it works

The headline pass — **P9, the representation bomb** — injects **N** dead static fields and **N** dead
static methods across a handful of decoy types. Every injected method body reads *all* N fields
(`ldsfld`) and calls *all* N methods (`call`), producing roughly **2·N² cross-reference edges**.

Three properties make this a good trade for the defender:

- **O(N) on disk, O(N²) for the analyzer.** Injected method bodies that share a body *shape* are
  byte-identical, so dnlib stores one method-body RVA per shape. On-disk growth is roughly linear
  (tens of kilobytes); the edge graph an analyzer must materialize is quadratic. Against the real
  `rea` CLI, a protected build crosses its **67,108,864-byte (64 MiB) representation budget** and
  returns `coverage.state = "unavailable"` with a `resource-limit` issue and **zero** recovered
  managed members. This is a denial *by exhaustion* — `rea` exits cleanly (~0), it does not crash.
- **Runtime-neutral.** Every injected member is unreachable — guarded so it is never executed and
  never JIT-compiled. The CLR loads and runs the protected assembly identically to the original,
  which the runtime-equivalence test suite proves on every build.
- **The seed is the secret, not the algorithm** (Kerckhoffs). The pass is hardened for
  open-sourcing: the CLI defaults to a cryptographically random per-build seed, and every would-be
  "strip signature" is randomized off that seed — decoy names drawn from wide pools across multiple
  namespace roots, uneven per-type member counts, several per-build body *shapes*, cross-boundary
  references from decoys into real code, and an opaque-guarded reachability anchor so a cheap
  mark-and-sweep can't prune the clique as a disconnected dead region. Pass `--seed` for reproducible
  builds.

The repository also ships the surrounding, behaviour-preserving passes that the preprint describes
(string encryption, opaque predicates, MBA constant substitution, CLR decoy archetypes, metadata
inflation, and gated raw-metadata tricks). `reaoverflow list` prints the full table with each pass's
safety class and evidence status.

| Pass | Mechanism | Class |
|------|-----------|-------|
| P1 | String encryption + lazy decryptor | safe |
| P2 | Opaque predicates + dead-branch decoy graph | safe |
| P3 | MBA / constant substitution | safe |
| P4 | CLR decoy-archetype injection (misdirection) | safe |
| P5 | Metadata inflation | safe |
| P6 | Raw-metadata parser break (duplicate / many / bad-name stream) | gated |
| P7 | Self-seal / entangle (anti-tamper) | gated |
| P8 | Runtime decoy telemetry | decorative |
| **P9** | **Representation bomb (quadratic cross-reference)** | **gated** |

`safe` = proven loadable and runtime-equivalent on a target. `gated` = behaviour-preserving but
non-standard, so it runs only when named explicitly and must pass per-target runtime tests.
`decorative` = carries no anti-analysis claim.

## Quickstart

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download).

**Build:**

```bash
dotnet build ReaOverflow.slnx -c Release
```

**Test** (51 tests — runtime equivalence, structural validity, determinism, signing, scale, and the
P9 hardening invariants):

```bash
dotnet test ReaOverflow.slnx
```

**Protect a sample assembly you own** with the representation bomb at maximum intensity:

```bash
dotnet run --project src/ReaOverflow.Cli -c Release -- \
    protect MyApp.dll -o MyApp.protected.dll --passes P9 --intensity maximum
```

Omit `--passes P9` to run the default balanced pipeline. Other commands:

```bash
# list every pass, its safety/status, and its default policy
dotnet run --project src/ReaOverflow.Cli -c Release -- list

# model an analyzer's charge for any assembly (a labelled, optimistic MODEL — not a measurement)
dotnet run --project src/ReaOverflow.Cli -c Release -- analyze MyApp.protected.dll

# runtime-equivalence + structural gates between original and protected
dotnet run --project src/ReaOverflow.Cli -c Release -- verify MyApp.dll MyApp.protected.dll
```

Builds are reproducible: the same input plus a fixed `--seed 0x…` produces byte-identical output.

## Reproduce the result

The headline exhaustion result is reproduced by an **opt-in** gate that drives the real third-party
`rea` CLI. It is **intentionally not part of `dotnet test`**, because it needs external tooling
(Node.js and the `rea` CLI on your `PATH`):

```bash
# builds the bundled sample, protects it with P9 (maximum), then gates it against the real rea CLI
bash scripts/rea-p9-exhaustion-gate.sh

# or test a pair you supply
bash scripts/rea-p9-exhaustion-gate.sh original.dll protected.dll
```

The gate asserts that `rea inspect-managed-members` decodes the **original** assembly completely, but
reports the **protected** build as `coverage = unavailable` with a `resource-limit` issue naming the
representation budget, and recovers **zero** managed members — while that same protected build still
loads and runs. (A PowerShell equivalent, `scripts/rea-p9-exhaustion-gate.ps1`, is also provided.)

## Limitations — honest scope

- **A trace-based or executing analyzer can defeat a purely-dead decoy.** The representation bomb's
  injected members are never executed, so a tool that actually *runs* or traces the program — or a
  constant-folding stripper that proves the guards are dead — can remove them and recover the real
  code. The hardening defeats signature, statistical, and cheap-reachability strippers; it does not
  defeat trace-based stripping. This is a cost-and-time deterrent, not impossibility.
- **The budget is a user-raisable ceiling.** `rea`'s representation budget is a per-command limit an
  operator can raise, which would delay and degrade analysis rather than block it outright.
- **The `analyze` command reports a *model*, not a measurement.** Its charge figures are a
  deliberately optimistic white-box model and are labelled as such; ground truth comes only from the
  opt-in gate above, run against the real `rea` CLI.
- **Protection invalidates existing signatures.** Re-sign after protecting (`--sign key.snk` for
  strong-name; Authenticode as a later step).

See [`docs/TECH-SPEC.md`](docs/TECH-SPEC.md) for the threat model, the per-pass design, and the full
honesty contract behind every claim above.

## Responsible use

This is defensive security research. Use it only on software you own or are explicitly authorized to
protect. Do not use it to hide malicious code, to evade security, AV, or EDR products, or to protect
software you do not own.

## Citation / paper

This repository accompanies a research preprint:

> *The representation bomb: a runtime-neutral metadata transform against automated reverse
> engineering.* arXiv:XXXX.XXXXX (to be added).

The exact artifact snapshot for this release is archived at Zenodo:
[doi:10.5281/zenodo.24294281](https://doi.org/10.5281/zenodo.24294281).

## License

Licensed under the **Apache License, Version 2.0** — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

The commercial **Tier-C** variant — which abandons the byte-identical / runtime-neutral guarantee to
resist trace-based and constant-folding strippers — is a **separate, proprietary work of SECBLOK Pty
Ltd** and is **not** included in or licensed under this repository. For commercial licensing
enquiries, contact `contact@secblok.io`.
