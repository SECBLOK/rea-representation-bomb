using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Passes;

/// <summary>
/// P8 — Runtime decoy telemetry (DECORATIVE, off by default). Injects a dead decoy type that looks
/// like live anti-analysis machinery: a debugger check, a telemetry beacon, an anti-tamper tick.
/// A live analyst stepping through, or an LLM reading the IL, treats these as real runtime defenses
/// and wastes effort on them — but nothing in the real program calls them, so they never execute.
///
/// HONESTY: Decorative — no security guarantee; this misleads an analyst only. Runtime safety (the
/// real program is unaffected) is covered by the RuntimeDecoyTelemetry_* tests. Off by default.
/// </summary>
public sealed class RuntimeDecoyTelemetryPass : IProtectionPass
{
    public string Id => "P8";
    public string Name => "Runtime decoy telemetry";
    public SafetyClass Safety => SafetyClass.Decorative;
    public EvidenceStatus Status => EvidenceStatus.DesignedFor;
    public bool DefaultFor(Intensity intensity) => false; // opt-in only (--passes P8)

    private static readonly string[] Roots = { "Helios", "Aurora", "Meridian", "Vertex", "Nimbus", "Cobalt" };

    public void Run(ProtectionContext ctx, PassReport report)
    {
        SeededPrng rng = ctx.Prng.Fork("p8-telemetry");
        if (!ctx.Budget.TryReserve(700))
        {
            report.Notes.Add("size budget reached; runtime decoy telemetry skipped");
            return;
        }

        string root = Roots[rng.Next(0, Roots.Length)];
        var t = new TypeDefUser($"{root}.Diagnostics", "RuntimeGuard", ctx.Cor.Object.TypeDefOrRef)
        {
            Attributes = dnlib.DotNet.TypeAttributes.NotPublic | dnlib.DotNet.TypeAttributes.AutoLayout
                         | dnlib.DotNet.TypeAttributes.AnsiClass | dnlib.DotNet.TypeAttributes.Sealed
                         | dnlib.DotNet.TypeAttributes.BeforeFieldInit,
        };
        ctx.Module.Types.Add(t);

        t.Fields.Add(new FieldDefUser("_tickState", new FieldSig(ctx.Cor.Int32),
            dnlib.DotNet.FieldAttributes.Private | dnlib.DotNet.FieldAttributes.Static));

        MethodDef core = AddMethod(ctx, rng, t, "Core", ctx.Cor.Int32, new[] { ctx.Cor.Int32 },
            Array.Empty<string>(), null, isCore: true);
        AddMethod(ctx, rng, t, "IsDebuggerPresent", ctx.Cor.Boolean, Array.Empty<TypeSig>(),
            new[] { "DEBUGGER_PRESENT", "managed attach detected", "JIT tracing enabled" }, core);
        AddMethod(ctx, rng, t, "EmitBeacon", ctx.Cor.Void, Array.Empty<TypeSig>(),
            new[] { "https://telemetry.internal.example/beacon", "X-Session-Id", "evt=launch", "sig=" }, core);
        AddMethod(ctx, rng, t, "AntiTamperTick", ctx.Cor.Int32, new TypeSig[] { ctx.Cor.Int32 },
            new[] { "integrity-tick", "checksum drift", "rollback epoch" }, core);

        report.Count("decoy_types", 1);
        report.Count("decoy_methods", 4);
        report.Notes.Add($"injected {root}.Diagnostics.RuntimeGuard (debugger check / telemetry beacon / anti-tamper tick — inert, never invoked)");
    }

    private static MethodDef AddMethod(ProtectionContext ctx, SeededPrng rng, TypeDef t, string name,
        TypeSig ret, TypeSig[] ps, string[] strings, MethodDef? core, bool isCore = false)
    {
        MethodSig sig = ps.Length == 0 ? MethodSig.CreateStatic(ret) : MethodSig.CreateStatic(ret, ps);
        var m = new MethodDefUser(name, sig, MethodImplAttributes.IL | MethodImplAttributes.Managed,
            dnlib.DotNet.MethodAttributes.Private | dnlib.DotNet.MethodAttributes.Static
                | dnlib.DotNet.MethodAttributes.HideBySig);
        var body = new CilBody { InitLocals = true, MaxStack = 8 };
        IList<Instruction> il = body.Instructions;

        if (isCore)
        {
            il.Add(OpCodes.Ldarg_0.ToInstruction());
            il.Add(Instruction.CreateLdcI4(unchecked((int)rng.NextUInt32())));
            il.Add(OpCodes.Xor.ToInstruction());
            il.Add(OpCodes.Ret.ToInstruction());
        }
        else
        {
            foreach (string s in strings) // emit every decoy string so the content reliably lands in #US
            {
                il.Add(OpCodes.Ldstr.ToInstruction(s));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            switch (ret.ElementType)
            {
                case ElementType.Void:
                    break;
                case ElementType.Boolean:
                    il.Add(Instruction.CreateLdcI4(unchecked((int)rng.NextUInt32())));
                    if (core is not null) il.Add(OpCodes.Call.ToInstruction(core));
                    il.Add(OpCodes.Ldc_I4_0.ToInstruction());
                    il.Add(OpCodes.Cgt_Un.ToInstruction());
                    break;
                default: // Int32
                    il.Add(Instruction.CreateLdcI4(unchecked((int)rng.NextUInt32())));
                    if (core is not null) il.Add(OpCodes.Call.ToInstruction(core));
                    break;
            }
            il.Add(OpCodes.Ret.ToInstruction());
        }

        m.Body = body;
        body.OptimizeMacros();
        t.Methods.Add(m);
        return m;
    }
}
