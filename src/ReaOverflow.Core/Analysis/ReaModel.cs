using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;

namespace ReaOverflow.Core.Analysis;

/// <summary>
/// A white-box <b>model</b> of REA's <c>ManagedDecodeBudget</c> (TECH-SPEC §1.1 / §6). It re-parses
/// an assembly and charges every item using REA's published per-item multipliers, then reports how
/// the modelled charge lands against REA's 64 MiB representation budget and whether a structural cap
/// is modelled as tripped. It executes NOTHING — pure static measurement, so it runs even when
/// antivirus blocks loading an obfuscated image.
///
/// <para><b>HONESTY — READ THIS (see <see cref="Disclaimer"/>).</b> This model is
/// <b>optimistic and is NOT measured against the real REA tool.</b> It has been validated against
/// <c>rea@6.7.0/6.9.0</c> and found to <b>over-predict</b>: the real <c>inspect-managed-members</c>
/// uses plain byte accounting of its ~8–10&#160;MB representation (well under the 64 MiB cap) and a
/// robust parser, so in testing REA <b>decoded every protected assembly completely</b> — it did
/// <i>not</i> exhaust its budget, and the modelled per-item multipliers (256×/row, 256×/instruction,
/// 256×/blob-byte, 512/type) do not reflect REA's actual charge. The <c>#JTD</c> "hard stop" and the
/// deep-nesting cap did <b>not</b> reproduce (REA parses straight through them); only the array-rank
/// cap landed. Empirically the protection is a <b>~20–23% representation-token tax</b> (P2 call-edges,
/// P3 field-accesses) plus P4 decoys — a real cost, not a denial. Treat <see cref="Result.CrossesBudget"/>
/// and <see cref="Result.AnyHardStop"/> as <b>modelled predictions, not observed REA behaviour</b>;
/// for ground truth run the empirical gate (<c>scripts/rea-token-gate.ps1</c> / <c>.sh</c>), which
/// drives the real <c>rea</c> CLI and asserts the measured token ratio.</para>
/// </summary>
public static class ReaModel
{
    /// <summary>
    /// Honesty label stamped onto every <c>analyze</c>/<c>verify</c> surface. The model is a design
    /// tool, not a measurement of REA; empirically it over-predicts (see the class remarks).
    /// </summary>
    public const string Disclaimer =
        "MODELLED / OPTIMISTIC — NOT measured against the real REA tool. Validated against rea@6.7.0/6.9.0, " +
        "this model OVER-PREDICTS: REA decoded every protected assembly completely (no budget exhaustion, " +
        "representation ~8-10 MB under the 64 MiB cap), and the #JTD 'hard stop' and deep-nesting cap did " +
        "NOT reproduce. The measured effect is a ~20-23% representation-token tax (P2/P3) plus P4 decoys. " +
        "For ground truth run the empirical gate: scripts/rea-token-gate.ps1 (or .sh).";
    // --- REA's exact ceilings and multipliers (TECH-SPEC §1.1) ---
    public const long RepresentationBudgetBytes = 64L * 1024 * 1024; // DEFAULT_MANAGED_REPRESENTATION_BYTES
    public const long SnapshotCapBytes = 128L * 1024 * 1024;         // DEFAULT_MANAGED_SNAPSHOT_BYTES
    public const int BytesPerRow = 256;                               // ManagedDecodeBudget.ts:52
    public const int BytesPerInstruction = 256;                       // ManagedMethodBodyReader.ts:165
    public const int BytesPerTokenOperand = 256;                      // +256 if the instr has a token operand
    public const int BlobChargePerByte = 256;                         // ...Core.ts:837,922 (blobLen × 256)
    public const int BytesPerType = 512;                              // ManagedMemberInspector.ts:236
    public const int MaxTypeNestingDepth = 64;                        // ManagedSignatureTypeNames.ts:29
    public const int MaxArrayRank = 32;                               // ...Core.ts:439
    public const int MinLocalCount = 1, MaxLocalCount = 65534;        // ...Core.ts:842

    public sealed record Charge(string Category, long Bytes, long Items);

    public sealed record Result(
        long FileBytes,
        IReadOnlyList<Charge> Breakdown,
        IReadOnlyList<string> TrippedCaps,
        bool JtdPresent,
        bool SnapshotRefusal,
        string PredictedStatus,
        bool ReaMetadataDenied = false,
        string? DenialReason = null)
    {
        public long TotalChargeBytes => Breakdown.Sum(c => c.Bytes);

        /// <summary>
        /// <b>Modelled</b> verdict: does the optimistic per-item charge reach REA's 64 MiB budget?
        /// This is a prediction of the model, NOT observed REA behaviour — empirically REA decodes
        /// typical protected assemblies completely (see <see cref="Disclaimer"/>).
        /// </summary>
        public bool CrossesBudget => TotalChargeBytes >= RepresentationBudgetBytes;
        public double BudgetFraction => (double)TotalChargeBytes / RepresentationBudgetBytes;

        /// <summary><b>Modelled</b> hard-stop prediction. <see cref="JtdPresent"/> is deliberately
        /// EXCLUDED: measured against rea@6.7.0/6.9.0, a <c>#JTD</c> stream is a no-op (REA parses
        /// straight through it), so it is reported as a structural fact, never a hard stop. Only a
        /// snapshot refusal (&gt;128 MiB whole-read) or a tripped structural cap counts here.</summary>
        public bool AnyHardStop => SnapshotRefusal || TrippedCaps.Count > 0;

        /// <summary>Always false: these numbers come from the model, never from running REA.</summary>
        public bool MeasuredAgainstRea => false;
    }

    public static Result Analyze(byte[] assemblyBytes)
    {
        var module = ModuleDefMD.Load(assemblyBytes);
        try { return Analyze(module, assemblyBytes.LongLength); }
        finally { module.Dispose(); }
    }

    public static Result Analyze(ModuleDefMD module, long fileBytes)
    {
        long rowCharge = 0, rowCount = 0;
        try
        {
            foreach (MDTable t in module.Metadata.TablesStream.MDTables)
            {
                if (t is null || t.IsEmpty) continue;
                rowCount += t.Rows;
                rowCharge += (long)t.Rows * BytesPerRow;
            }
        }
        catch { /* tables unreadable → row charge stays 0, still a valid model */ }

        long typeCount = 0, instrCharge = 0, instrCount = 0, tokenOps = 0;
        long blobCharge = 0, blobBytes = 0;
        long strCharge = 0; var seenStrings = new HashSet<string>();
        var caps = new List<string>();
        var scan = new SigScan();

        foreach (TypeDef type in module.GetTypes())
        {
            typeCount++;

            foreach (FieldDef f in type.Fields)
                EstimateTypeSigLen(f.FieldSig?.Type, scan, 0);

            foreach (MethodDef m in type.Methods)
            {
                // Method signature blob (charged 256× its length).
                int sigLen = EstimateMethodSigLen(m, scan);
                blobBytes += sigLen;
                blobCharge += (long)sigLen * BlobChargePerByte;

                if (!m.HasBody || m.Body is null) continue;

                // LocalVarSig blob (the 256× lever).
                int localCount = m.Body.Variables?.Count ?? 0;
                if (localCount > 0)
                {
                    if (localCount < MinLocalCount || localCount > MaxLocalCount)
                        caps.Add($"LocalVarSig local count {localCount} outside 1..65534 ({m.FullName})");
                    int lsLen = EstimateLocalSigLen(m, scan);
                    blobBytes += lsLen;
                    blobCharge += (long)lsLen * BlobChargePerByte;
                }

                foreach (Instruction instr in m.Body.Instructions)
                {
                    instrCount++;
                    instrCharge += BytesPerInstruction;
                    if (instr.Operand is IMDTokenProvider || instr.Operand is string)
                    {
                        instrCharge += BytesPerTokenOperand;
                        tokenOps++;
                    }
                    if (instr.Operand is string s && seenStrings.Add(s))
                        strCharge += (long)s.Length * 6 + 2;
                }
            }
        }

        if (scan.MaxDepth > MaxTypeNestingDepth)
            caps.Add($"signature type-name nesting depth {scan.MaxDepth} > {MaxTypeNestingDepth} (names unresolved → name_sha256 null)");
        if (scan.MaxRank > MaxArrayRank)
            caps.Add($"array rank {scan.MaxRank} > {MaxArrayRank} (unsupported-signature → member partial)");

        bool jtd = false;
        try { jtd = module.Metadata.AllStreams.Any(s => s.Name == "#JTD"); } catch { }

        // MEASURED metadata-layer analysis-denial (P6). A duplicate stream name or >64 streams makes
        // the real rea reader throw at layout parse and report metadata=malformed with ZERO members
        // across all managed inspectors (exit 0); the CLR/dnlib ignore the extra streams so the app
        // still loads. This is a MEASURED fact (rea@6.7.0 and 6.9.0, 2026-11-16 fuzz campaign), not a modelled
        // prediction — re-check with scripts/rea-p6-denial-gate.ps1 / .sh.
        string? denialReason = null;
        try
        {
            var names = module.Metadata.AllStreams.Select(s => s.Name ?? string.Empty).ToList();
            var dup = names.GroupBy(n => n).FirstOrDefault(g => g.Count() > 1);
            string? nonPrintable = names.FirstOrDefault(n => n.Any(ch => ch < 0x20 || ch > 0x7e));
            if (dup is not null)
                denialReason = $"duplicate metadata stream '{dup.Key}'";
            else if (names.Count > 64)
                denialReason = $"{names.Count} metadata streams (> rea's admitted 64)";
            else if (nonPrintable is not null)
                denialReason = "metadata stream name with a non-printable byte";
        }
        catch { }
        bool reaDenied = denialReason is not null;

        bool snapshot = fileBytes > SnapshotCapBytes;

        var breakdown = new List<Charge>
        {
            new("metadata rows (×256)", rowCharge, rowCount),
            new("types (×512)", (long)typeCount * BytesPerType, typeCount),
            new("CIL instructions (×256, +256 token)", instrCharge, instrCount),
            new("signature/LocalVarSig blobs (×256)", blobCharge, blobBytes),
            new("#US strings (×6 +2)", strCharge, seenStrings.Count),
        };

        long total = breakdown.Sum(c => c.Bytes);
        string status = PredictStatus(snapshot, jtd, caps, total);
        return new Result(fileBytes, breakdown, caps, jtd, snapshot, status, reaDenied, denialReason);
    }

    private static string PredictStatus(bool snapshot, bool jtd, List<string> caps, long total)
    {
        if (snapshot) return "unavailable — snapshot cap (>128 MiB whole-read refusal)";
        // #JTD is NOT a hard stop (measured no-op vs real REA); it is surfaced as an informational
        // suffix, never as an "unsupported-metadata" verdict the tool would be lying to assert.
        string jtdNote = jtd ? " [#JTD present — MEASURED no-op vs REA, not a hard stop]" : "";
        var parts = new List<string>();
        if (caps.Count > 0) parts.Add($"{caps.Count} cap(s) tripped");
        if (total >= RepresentationBudgetBytes) parts.Add("representation budget exhausted (≥64 MiB)");
        if (parts.Count == 0) return "ok — full coverage (budget not exhausted, no caps)" + jtdNote;
        return "partial/degraded — " + string.Join("; ", parts) + jtdNote;
    }

    // --- signature-blob length estimators (reconstruct on-disk blob length from decoded sig) ---

    /// <summary>Accumulates the worst-case array rank and signature-nesting depth seen while scanning.</summary>
    private sealed class SigScan
    {
        public int MaxRank;
        public int MaxDepth;
    }

    private static int EstimateMethodSigLen(MethodDef m, SigScan scan)
    {
        MethodSig? sig = m.MethodSig;
        if (sig is null) return 2;
        int n = 1 + 1; // calling convention + param count
        if (sig.Generic) n += 1;
        n += EstimateTypeSigLen(sig.RetType, scan, 0);
        foreach (TypeSig p in sig.Params) n += EstimateTypeSigLen(p, scan, 0);
        return n;
    }

    private static int EstimateLocalSigLen(MethodDef m, SigScan scan)
    {
        var locals = m.Body.Variables;
        if (locals is null || locals.Count == 0) return 0;
        int n = 1 + 2; // LOCAL_SIG + compressed local count
        foreach (Local l in locals) n += EstimateTypeSigLen(l.Type, scan, 0);
        return n;
    }

    /// <summary>
    /// Reconstructs the approximate on-disk blob length of a signature element, tracking the
    /// maximum array rank and the maximum nesting depth (REA's name-building cap). Depth-guarded
    /// so pathological nesting cannot blow the stack.
    /// </summary>
    private static int EstimateTypeSigLen(TypeSig? sig, SigScan scan, int depth)
    {
        if (sig is null) return 1;
        if (depth > scan.MaxDepth) scan.MaxDepth = depth;
        if (depth > 4096) return 1; // stack guard
        switch (sig)
        {
            case CorLibTypeSig:
                return 1;
            case GenericInstSig g:
            {
                int n = 2 + 1; // GENERICINST + base element type + arg count
                n += EstimateTypeSigLen(g.GenericType, scan, depth + 1);
                foreach (TypeSig a in g.GenericArguments) n += EstimateTypeSigLen(a, scan, depth + 1);
                return n;
            }
            case ArraySig a:
            {
                if (a.Rank > scan.MaxRank) scan.MaxRank = (int)a.Rank;
                int rank = (int)a.Rank;
                // ARRAY + elem + rank + numSizes + sizes + numLoBounds + loBounds
                return 1 + EstimateTypeSigLen(a.Next, scan, depth + 1) + 1 + 1 + rank + 1 + rank;
            }
            case SZArraySig sz:
                return 1 + EstimateTypeSigLen(sz.Next, scan, depth + 1);
            case ClassOrValueTypeSig:
                return 1 + 3; // element type + compressed TypeDefOrRef coded token (~1-4, assume 3)
            case GenericSig:
                return 2; // VAR/MVAR + number
            case PtrSig p:
                return 1 + EstimateTypeSigLen(p.Next, scan, depth + 1);
            case ByRefSig b:
                return 1 + EstimateTypeSigLen(b.Next, scan, depth + 1);
            case ModifierSig mod:
                return 1 + 3 + EstimateTypeSigLen(mod.Next, scan, depth + 1);
            case PinnedSig pin:
                return 1 + EstimateTypeSigLen(pin.Next, scan, depth + 1);
            case FnPtrSig:
                return 4;
            default:
                return 1 + EstimateTypeSigLen(sig.Next, scan, depth + 1);
        }
    }
}
