using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Passes;

/// <summary>
/// P3 — Mixed Boolean-Arithmetic (MBA) constant substitution. Replaces each selected
/// <c>ldc.i4 C</c> in user code with the identity <c>(C ^ R) + 2·(C &amp; R) − R</c>, which is
/// exactly C for any seeded R (because <c>C + R = (C ^ R) + 2·(C &amp; R)</c>). The literal value C
/// no longer appears as a single constant; a reader/LLM must fold mixed bitwise+arithmetic to
/// recover it, and the extra instructions raise REA's per-instruction charge.
///
/// Correctness: the substitution is an algebraic identity, so behaviour is unchanged — verified by
/// executing a P3-protected build in-memory (MbaSubstitution_* tests). The existing ldc instruction
/// is reused as the first opcode of the sequence, so any branch that targeted it stays valid.
///
/// HONESTY: DesignedFor opacity, not secrecy — R and the folded constants are still in the IL, so
/// constant-folding recovers C. The value is defeating naive reads and inflating analysis cost.
/// </summary>
public sealed class MbaSubstitutionPass : IProtectionPass
{
    public string Id => "P3";
    public string Name => "MBA constant substitution";
    public SafetyClass Safety => SafetyClass.Safe;
    // Verified: MbaSubstitution_Executes_And_Is_Equivalent runs the rewritten sample in-memory.
    public EvidenceStatus Status => EvidenceStatus.Verified;
    public bool DefaultFor(Intensity intensity) => intensity >= Intensity.Balanced;

    private const int EstPerSiteBytes = 18;

    public void Run(ProtectionContext ctx, PassReport report)
    {
        SeededPrng rng = ctx.Prng.Fork("p3-mba");
        List<MethodDef> targets = ctx.UserMethods().ToList();

        int sites = 0;
        bool budgetHit = false;
        foreach (MethodDef m in targets)
        {
            // Promote every short branch (br.s/bgt.s/…, ±127-byte reach) to its long form BEFORE we
            // splice instructions in. Each substitution inserts 6 instructions mid-body; an insertion
            // that lands between a short branch and its target pushes the target out of reach, and the
            // branch is then silently mis-encoded to a neighbour — which is how a loop's entry/back
            // edge got redirected and corrupted control flow (observed as IndexOutOfRange on real
            // code). Long branches have a 4-byte offset that can't overflow; OptimizeBranches() below
            // re-shortens the ones that are safe once the final offsets are known.
            m.Body.SimplifyBranches();
            IList<Instruction> ins = m.Body.Instructions;
            for (int i = 0; i < ins.Count; i++)
            {
                Instruction instr = ins[i];
                if (!instr.IsLdcI4()) continue;
                if (!rng.NextBool()) continue; // seeded ~50% subset — keeps runtime bodies sane

                if (!ctx.Budget.TryReserve(EstPerSiteBytes))
                {
                    budgetHit = true;
                    goto done;
                }

                int c = instr.GetLdcI4Value();
                int r = unchecked((int)rng.NextUInt32());
                int a = c ^ r;
                int b = c & r;

                // Reuse the current instruction as "ldc.i4 a" (preserves branch targets to it),
                // then insert: ldc.i4 b; ldc.i4.2; mul; add; ldc.i4 r; sub  →  (a + 2b) - r == c
                instr.OpCode = OpCodes.Ldc_I4;
                instr.Operand = a;
                var seq = new[]
                {
                    Instruction.CreateLdcI4(b),
                    OpCodes.Ldc_I4_2.ToInstruction(),
                    OpCodes.Mul.ToInstruction(),
                    OpCodes.Add.ToInstruction(),
                    Instruction.CreateLdcI4(r),
                    OpCodes.Sub.ToInstruction(),
                };
                for (int k = 0; k < seq.Length; k++) ins.Insert(i + 1 + k, seq[k]);
                i += seq.Length;
                sites++;
            }
            m.Body.OptimizeMacros();
            m.Body.OptimizeBranches();
        }
    done:
        report.Count("constants_substituted", sites);
        report.EstimatedBytesAdded = (long)sites * EstPerSiteBytes;
        report.Notes.Add("identity: (C^R) + 2·(C&R) − R == C (MBA; opacity, not secrecy)");
        if (budgetHit) report.Notes.Add("size budget reached; remaining constants left as-is");
    }
}
