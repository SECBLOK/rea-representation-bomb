using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Passes;

/// <summary>
/// P2 — Opaque predicates + dead-branch decoys. Prepends to each user method an always-true
/// predicate that guards a never-executed decoy block (a call into an inert decoy method). The
/// real body is the branch target, so runtime behaviour is unchanged (Safe) — the decoy is dead
/// code that only the CLR's unreached path and a static analyzer ever "see".
///
/// Effect vs REA: inflates CIL instruction count (256 B each), adds call edges REA must record,
/// and injects plausible-but-fake control flow that an LLM treats as real logic. The predicate
/// reads a seeded static field so the condition isn't a bare literal a reader folds at a glance.
/// Correctness rests on the predicate being unconditionally true: <c>(_k | 1)</c> is nonzero for
/// every value of <c>_k</c>, so <c>brtrue</c> is always taken and the decoy never runs.
/// </summary>
public sealed class OpaquePredicatePass : IProtectionPass
{
    public string Id => "P2";
    public string Name => "Opaque predicates + dead-branch decoys";
    public SafetyClass Safety => SafetyClass.Safe;
    // Verified: OpaquePredicate_Executes_And_Is_Equivalent runs the rewritten sample in-memory and
    // asserts identical output (P2 adds no crypto, so the CLR loads it even on a Defender host).
    public EvidenceStatus Status => EvidenceStatus.Verified;
    public bool DefaultFor(Intensity intensity) => intensity >= Intensity.Balanced;

    // Rough disk cost of one injected predicate+decoy site (6 short instructions).
    private const int EstPerSiteBytes = 24;

    public void Run(ProtectionContext ctx, PassReport report)
    {
        SeededPrng rng = ctx.Prng.Fork("p2-opaque");

        // Snapshot targets BEFORE injecting helpers so we never wrap our own decoy/field init.
        List<MethodDef> targets = ctx.UserMethods().ToList();

        FieldDef kField = EnsureSeedField(ctx, rng);
        MethodDef decoy = BuildDecoyMethod(ctx, rng);
        int decoyConst = unchecked((int)rng.NextUInt32());

        int sites = 0;
        foreach (MethodDef m in targets)
        {
            IList<Instruction> ins = m.Body.Instructions;
            if (ins.Count == 0) continue;
            if (!ctx.Budget.TryReserve(EstPerSiteBytes))
            {
                report.Notes.Add("size budget reached; remaining methods left unguarded");
                break;
            }

            Instruction firstOriginal = ins[0];
            var injected = new Instruction[]
            {
                OpCodes.Ldsfld.ToInstruction(kField),
                OpCodes.Ldc_I4_1.ToInstruction(),
                OpCodes.Or.ToInstruction(),
                OpCodes.Brtrue.ToInstruction(firstOriginal), // always taken → skips the decoy
                Instruction.CreateLdcI4(decoyConst),          // dead: never executed at runtime
                OpCodes.Call.ToInstruction(decoy),            // ...but a real call edge for REA
            };
            for (int i = 0; i < injected.Length; i++)
                ins.Insert(i, injected[i]);

            m.Body.OptimizeMacros();
            m.Body.OptimizeBranches();
            sites++;
        }

        report.Count("methods_guarded", sites);
        report.Count("decoy_call_edges", sites);
        report.EstimatedBytesAdded = (long)sites * EstPerSiteBytes + 80; // + field/decoy overhead
        report.Notes.Add($"opaque predicate: (seededField | 1) != 0 — always true, decoy is dead code");
    }

    private static FieldDef EnsureSeedField(ProtectionContext ctx, SeededPrng rng)
    {
        var field = new FieldDefUser(
            rng.NextIdentifier(rng.Next(8, 14)),
            new FieldSig(ctx.Cor.Int32),
            // Assembly (internal) visibility: user methods in other types must read it at runtime.
            dnlib.DotNet.FieldAttributes.Assembly | dnlib.DotNet.FieldAttributes.Static);
        ctx.RuntimeType.Fields.Add(field);

        // Initialise it in the runtime type's static constructor.
        MethodDef cctor = ctx.RuntimeType.FindOrCreateStaticConstructor();
        cctor.Body ??= new CilBody();
        IList<Instruction> cil = cctor.Body.Instructions;
        int seedVal = unchecked((int)rng.NextUInt32());
        cil.Insert(0, OpCodes.Stsfld.ToInstruction(field));
        cil.Insert(0, Instruction.CreateLdcI4(seedVal));
        if (cil.Count == 0 || cil[cil.Count - 1].OpCode.Code != Code.Ret)
            cil.Add(OpCodes.Ret.ToInstruction());
        cctor.Body.OptimizeMacros();
        return field;
    }

    /// <summary>An inert, valid-IL decoy method: <c>static void Decoy(int x)</c> that does fake work.</summary>
    private static MethodDef BuildDecoyMethod(ProtectionContext ctx, SeededPrng rng)
    {
        var sig = MethodSig.CreateStatic(ctx.Cor.Void, ctx.Cor.Int32);
        var m = new MethodDefUser(rng.NextIdentifier(rng.Next(8, 14)), sig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            // Assembly (internal): called from user methods in other types.
            dnlib.DotNet.MethodAttributes.Assembly | dnlib.DotNet.MethodAttributes.Static
                | dnlib.DotNet.MethodAttributes.HideBySig);
        ctx.RuntimeType.Methods.Add(m);

        var body = new CilBody { MaxStack = 4 };
        IList<Instruction> il = body.Instructions;
        il.Add(OpCodes.Ldarg_0.ToInstruction());
        il.Add(Instruction.CreateLdcI4(unchecked((int)rng.NextUInt32())));
        il.Add(OpCodes.Xor.ToInstruction());
        il.Add(Instruction.CreateLdcI4(unchecked((int)rng.NextUInt32() | 1)));
        il.Add(OpCodes.Mul.ToInstruction());
        il.Add(OpCodes.Pop.ToInstruction());
        il.Add(OpCodes.Ret.ToInstruction());
        m.Body = body;
        body.OptimizeMacros();
        return m;
    }
}
