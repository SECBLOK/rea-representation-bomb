# Release hygiene

**Rule: ReaOverflow is distributed as source. No compiled binaries in the git tree or on a
release page — ever.**

## Why this exists

A P9-protected assembly is, by design, dense/obfuscated .NET metadata. To an automated malware
scanner that is indistinguishable from a packer — the same surface features legitimate packers
and malware share. GitHub runs heuristic scanning on **release assets**, and a protected `.exe`
uploaded as a release binary gets **auto-flagged**, which can suspend the repo and the account.
This already happened once. It is a false positive, but the fix is not to argue with the
scanner — it is to **not ship binaries**.

## What to do instead

- **Repository:** source only. `bin/`, `obj/`, `out/` are `.gitignore`d; signing keys
  (`*.snk`, `*.pfx`, `*.p12`) are too. The guard script enforces that nothing binary is tracked.
- **Releases (GitHub/GitLab):** a release is **source + release notes**. Do **not** attach
  `.exe`, `.dll`, `.nupkg`, or any compiled artifact as a release asset.
- **Reproduction / sample protected binaries:** publish them in the **Zenodo artifact archive**
  (which mints a DOI and does not run GitHub's release-asset malware scanning). The paper cites
  the DOI. Readers who want to reproduce either download from Zenodo or build from source and run
  the tool themselves.
- **Building:** readers run `dotnet build` / `dotnet run --project src/ReaOverflow.Cli -- protect …`
  to generate their own protected samples locally. No prebuilt binary needs to ship.

## The guard

`scripts/check-release-hygiene.sh` (and `.ps1`) scans `git ls-files` for compiled binaries and
key files and fails if any are tracked. Run it before cutting a release, and in CI if/when CI is
added:

```bash
scripts/check-release-hygiene.sh
```

The script also prints the release-asset rule as a reminder — that part (what you attach to a
release page) lives outside git and must be followed by hand.

## Release checklist

- [ ] `scripts/check-release-hygiene.sh` passes (no tracked binaries/keys).
- [ ] Release contains **source + notes only** — no `.exe`/`.dll`/`.nupkg` assets.
- [ ] Any sample protected binaries uploaded to **Zenodo**, not the release page.
- [ ] (When publishing the paper) artifact cited by **Zenodo DOI**, not a raw binary URL.
- [ ] GitHub mirror, if any, is **source only** and only after the account suspension is cleared.
