using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReaOverflow.Core.Analysis;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Passes;

/// <summary>
/// P5 — Metadata inflation (the §2 size thesis made concrete). Injects a handful of dead static
/// methods whose <c>LocalVarSig</c> blobs are large. The <b>model</b> charges every signature blob at
/// 256× its on-disk length, so a few hundred KB of locals is modelled as a ≥64 MiB representation
/// charge. ⚠️ MEASURED: against the real <c>rea</c> CLI this multiplier does <b>not</b> apply (REA
/// uses plain byte accounting) and REA decodes the result completely — this pass adds real metadata
/// volume (a modest token tax), <b>not</b> budget exhaustion. See TECH-SPEC's empirical correction.
///
/// At Maximum intensity it also plants a rank-33 array local (rank &gt; 32 → <c>unsupported-signature</c>)
/// in one dead method — the one structural cap-attack that actually bit REA (handover, rea@6.9.0).
/// ⚠️ The deep-nesting cap-attack was <b>CUT</b>: measured against rea@6.7.0 it was a no-op at every
/// depth tried (70 … 520 → 0 null names, coverage "complete"), and rea@6.9.0 ignored it too. REA
/// resolves arbitrarily deep <c>SZArray</c> nesting, so the lever is retired; only array-rank remains.
///
/// Runtime safety: every injected method is dead — nothing calls it, so the CLR never JITs it and
/// never resolves these signatures. Validated by executing a P5-protected build in-memory (the
/// MetadataInflation_* tests). All growth is vetoed by <see cref="SizeBudget"/>.
///
/// HONESTY: this is DesignedFor. Numbers shown by <c>analyze</c> are <b>modelled and optimistic</b>,
/// not measured on REA; the real effect is measured by <c>scripts/rea-token-gate</c>.
/// </summary>
public sealed class MetadataInflationPass : IProtectionPass
{
    public string Id => "P5";
    public string Name => "Metadata inflation (modelled budget attack; array-rank cap bites REA)";
    public SafetyClass Safety => SafetyClass.Safe;
    public EvidenceStatus Status => EvidenceStatus.DesignedFor;
    public bool DefaultFor(Intensity intensity) => intensity >= Intensity.Balanced;

    private const int LocalsPerMethod = 65000;      // under the 65534 LocalVarSig ceiling
    private const int HighArrayRank = 33;           // > MAX_ARRAY_RANK (32) — the lever that bites REA

    public void Run(ProtectionContext ctx, PassReport report)
    {
        SeededPrng rng = ctx.Prng.Fork("p5-inflate");
        long target = ReaModel.RepresentationBudgetBytes; // aim to cross REA's 64 MiB budget
        bool capLever = ctx.Options.Intensity >= Intensity.Maximum;

        long addedCharge = 0, addedDisk = 0;
        int methods = 0;
        bool budgetHit = false, capsPlanted = false;

        while (addedCharge < target)
        {
            bool plantCaps = capLever && !capsPlanted;
            int locals = LocalsPerMethod;
            // on-disk blob ≈ one byte per simple int local + a little header/overhead
            int diskEst = locals + 48 + (plantCaps ? HighArrayRank * 2 + 8 : 0);
            if (!ctx.Budget.TryReserve(diskEst))
            {
                budgetHit = true;
                break;
            }

            int blobLen = BuildInflationMethod(ctx, rng, locals, plantCaps);
            addedCharge += (long)blobLen * ReaModel.BlobChargePerByte;
            addedDisk += diskEst;
            methods++;
            if (plantCaps) capsPlanted = true;
        }

        report.Count("inflation_methods", methods);
        report.Count("modelled_charge_added_bytes", addedCharge);
        report.EstimatedBytesAdded = addedDisk;
        report.Notes.Add($"MODELLED REA charge added ≈ {addedCharge / (1024.0 * 1024.0):F1} MiB from {methods} dead LocalVarSig blobs (256× — model only; real REA decodes completely)");
        if (capsPlanted)
            report.Notes.Add($"cap-trip planted: array rank {HighArrayRank} (>32 → unsupported-signature; MEASURED to bite REA). Deep-nesting lever CUT (measured no-op at any depth).");
        if (budgetHit)
            report.Notes.Add("size budget reached before the MODELLED charge crossed 64 MiB (model only — real REA is not exhausted either way)");
    }

    /// <summary>Builds a dead static method with a large LocalVarSig; returns the estimated blob length.</summary>
    private static int BuildInflationMethod(ProtectionContext ctx, SeededPrng rng, int locals, bool plantCaps)
    {
        var sig = MethodSig.CreateStatic(ctx.Cor.Void);
        var m = new MethodDefUser(rng.NextIdentifier(rng.Next(8, 14)), sig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            dnlib.DotNet.MethodAttributes.Private | dnlib.DotNet.MethodAttributes.Static
                | dnlib.DotNet.MethodAttributes.HideBySig);
        ctx.RuntimeType.Methods.Add(m);

        // InitLocals=false: never called, so no zeroing semantics ever apply.
        var body = new CilBody { InitLocals = false, MaxStack = 1 };
        int blobLen = 1 + 2; // LOCAL_SIG + compressed count

        for (int i = 0; i < locals; i++)
        {
            body.Variables.Add(new Local(ctx.Cor.Int32));
            blobLen += 1;
        }

        if (plantCaps)
        {
            // Rank-33 multidim array: rank > 32 trips unsupported-signature. This is the one
            // structural cap-attack measured to actually bite REA (handover, rea@6.9.0). The former
            // deep-nesting lever was cut — REA resolves arbitrarily deep SZArray nesting (measured).
            var hiRank = new ArraySig(ctx.Cor.Int32, (uint)HighArrayRank);
            body.Variables.Add(new Local(hiRank));
            blobLen += 3 + HighArrayRank * 2;
        }

        body.Instructions.Add(OpCodes.Ret.ToInstruction());
        m.Body = body;
        return blobLen;
    }
}
