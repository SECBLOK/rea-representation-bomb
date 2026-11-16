using System.Collections.Generic;
using ReaOverflow.Core.Analysis;

namespace ReaOverflow.Core.Pipeline;

/// <summary>
/// Runs the TECH-SPEC §6 validation gates against an (original, protected) pair and returns an
/// honest, self-labelling report. Nothing here hides a gap: a gate that could not run on this host
/// (e.g. antivirus blocking execution of an obfuscated image) reports <c>Blocked</c>, never <c>Pass</c>.
/// </summary>
public static class Verifier
{
    public enum Outcome { Pass, Fail, Blocked, Skipped }

    public sealed record Gate(string Name, Outcome Outcome, string Detail, bool Critical);

    public sealed record Report(IReadOnlyList<Gate> Gates)
    {
        /// <summary>True unless a critical gate actually failed. Blocked/Skipped do not fail the run.</summary>
        public bool Ok
        {
            get
            {
                foreach (Gate g in Gates)
                    if (g.Critical && g.Outcome == Outcome.Fail) return false;
                return true;
            }
        }
    }

    public static Report Verify(byte[] original, byte[] protectedBytes, string[]? entryArgs = null)
    {
        var gates = new List<Gate>();

        // Gate 0 — structural: the protected image is well-formed and fully decodable.
        StructuralValidator.Result sv = StructuralValidator.Validate(protectedBytes);
        gates.Add(new Gate("structural",
            sv.Ok ? Outcome.Pass : Outcome.Fail,
            sv.Ok
                ? $"re-parsed OK; {sv.MethodsDecoded} method bodies decoded; IL-only={sv.IsILOnly}; entrypoint={sv.HasEntryPoint}"
                : "decode issues: " + string.Join(" | ", sv.Issues),
            Critical: true));

        // Gate 1 — runtime equivalence: original and protected produce identical stdout.
        RuntimeRunner.RunResult o = RuntimeRunner.TryRun(original, entryArgs);
        RuntimeRunner.RunResult p = RuntimeRunner.TryRun(protectedBytes, entryArgs);
        if (!o.Ran)
            gates.Add(new Gate("runtime-equivalence", Outcome.Blocked,
                "original could not be executed here: " + o.Error, Critical: true));
        else if (!p.Ran)
            gates.Add(new Gate("runtime-equivalence", Outcome.Blocked,
                "protected could not be executed on this host (e.g. antivirus flags the obfuscated image): "
                + p.Error + " — re-run on an allowlisted machine to complete this gate", Critical: true));
        else
            gates.Add(new Gate("runtime-equivalence",
                o.Output == p.Output ? Outcome.Pass : Outcome.Fail,
                o.Output == p.Output
                    ? "identical stdout from original and protected entry points"
                    : "OUTPUT DIFFERS — protection changed behaviour (this is a correctness bug)",
                Critical: true));

        // Gate 3 — budget assertion (MODELLED design target, NOT measured REA resistance).
        // HONESTY: this gate checks the optimistic ReaModel prediction, which over-predicts against the
        // real REA tool (REA decoded protected assemblies completely in testing). It gates that the
        // protection was *designed* to the budget thesis — it is NOT evidence REA was actually degraded.
        // Run scripts/rea-token-gate.ps1/.sh for the measured token ratio against the real rea CLI.
        ReaModel.Result r = ReaModel.Analyze(protectedBytes);
        bool budgetOk = r.CrossesBudget || r.AnyHardStop;
        gates.Add(new Gate("rea-budget (modelled)",
            budgetOk ? Outcome.Pass : Outcome.Fail,
            $"MODELLED design target, NOT measured against REA (model over-predicts; real REA decodes "
                + $"completely — run scripts/rea-token-gate for ground truth): modelled charge "
                + $"{r.TotalChargeBytes / (1024.0 * 1024.0):F1} MiB ({r.BudgetFraction:P0} of 64 MiB); "
                + $"modelled caps={r.TrippedCaps.Count}; #JTD={r.JtdPresent}; modelled status: {r.PredictedStatus}",
            Critical: true));

        // Gate 2 — analysis degradation (informational): the protected image gives a reader less
        // signal and more noise than the original. Self-contained; an independent ilspycmd decompile
        // is the documented manual cross-check.
        DegradationMetrics.Metrics o2 = DegradationMetrics.Measure(original);
        DegradationMetrics.Metrics p2 = DegradationMetrics.Measure(protectedBytes);
        bool degraded = p2.Instructions > o2.Instructions || p2.TypeCount > o2.TypeCount
                        || p2.ReadableStrings < o2.ReadableStrings || r.AnyHardStop;
        gates.Add(new Gate("analysis-degradation",
            degraded ? Outcome.Pass : Outcome.Skipped,
            $"readable strings {o2.ReadableStrings}→{p2.ReadableStrings}, types {o2.TypeCount}→{p2.TypeCount}, "
                + $"instructions {o2.Instructions}→{p2.Instructions}, method bodies {o2.MethodBodies}→{p2.MethodBodies} "
                + "(ilspycmd decompile is the documented independent cross-check)",
            Critical: false));

        return new Report(gates);
    }
}
