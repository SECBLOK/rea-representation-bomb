using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Passes;

/// <summary>
/// P4 — CLR decoy archetypes. Injects whole decoy types that <i>look like</i> real protection
/// machinery — a license ring, a feature-tier matrix, a hardware-dongle shim (with a genuine
/// P/Invoke declaration), an update handshake, a KDF vault, a telemetry beacon and an entitlement
/// store — complete with believable fields, realistic string constants, and a <b>dense, interconnected
/// call graph</b>: every archetype calls into a sibling, holds a typed reference to another decoy,
/// and a central <c>SubsystemBroker</c> orchestrates them all. A reader/LLM treats this as a genuine,
/// wired-together protection subsystem and draws wrong conclusions about how the program is protected.
///
/// <para><b>Multi-domain coverage (post-v2).</b> The set spans both security-shaped archetypes
/// (licensing, dongle, KDF, telemetry) <i>and</i> functional application subsystems — a serialization
/// registry, a protocol router and a cache coordinator. v2 measured that misdirection is
/// <i>goal-dependent</i>: a security/licensing-audit-framed agent was fully derailed while a
/// <i>purpose</i>-framed agent dismissed the security decoys. The functional archetypes are
/// <b>DesignedFor</b> (not yet re-measured) — they exist so a wider range of analyst goals
/// (data-flow, network, storage) bite, not only the audit framing.</para>
///
/// <para><b>Interconnection (the measured misdirection win).</b> REA records cross-type call edges and
/// field accesses as real inter-subsystem wiring, so denser, interconnected decoys are harder to
/// dismiss than isolated stubs. This pass adds, measured against the real <c>rea</c> CLI:
/// (a) decoy→decoy call edges and typed cross-fields, (b) an orchestrator hub with high out-degree,
/// and (c) a bounded set of <b>real→decoy</b> call edges — a handful of the user's own methods gain an
/// opaque-false-guarded, never-executed call into the decoy broker, so the decoys look <i>used by real
/// code</i>. The real→decoy edges reuse P2's proven opaque-predicate pattern (guard is always true →
/// the decoy call is dead), skip compiler-generated state machines (<see cref="MethodTargeting"/>),
/// and are covered by the DecoyArchetype_* runtime-equivalence tests.</para>
///
/// This is OUR archetype map, not BLA's. The decoy namespace root is seeded, so two projects get
/// different-looking decoy sets (harder to fingerprint and strip). Every decoy is inert — nothing in
/// the real program's live path reaches one (the real→decoy edges are dead code), so the CLR never
/// JITs a decoy and behaviour is unchanged.
///
/// HONESTY: Decorative — decoys mislead a reader/LLM; they give no cryptographic guarantee and a
/// determined analyst can discount them. They are the durable, measured misdirection (REA surfaces
/// them as real), not budget exhaustion. Runtime-equivalence is covered by the DecoyArchetype_* tests.
/// </summary>
public sealed class DecoyArchetypePass : IProtectionPass
{
    public string Id => "P4";
    public string Name => "CLR decoy archetypes (interconnected)";
    public SafetyClass Safety => SafetyClass.Decorative;
    public EvidenceStatus Status => EvidenceStatus.DesignedFor;
    public bool DefaultFor(Intensity intensity) => intensity >= Intensity.Balanced;

    private static readonly string[] Roots =
        { "Helios", "Aurora", "Meridian", "Vertex", "Nimbus", "Cobalt", "Pinnacle", "Ardent", "Solstice", "Keystone" };

    private const int EstTypeBytes = 720;      // rough disk cost per decoy archetype (now with cross-wiring)
    private const int EstEdgeBytes = 10;       // per real->decoy guarded edge
    private const int MaxRealToDecoyEdges = 12; // bound the real-body edits

    public void Run(ProtectionContext ctx, PassReport report)
    {
        SeededPrng rng = ctx.Prng.Fork("p4-decoys");
        string root = Roots[rng.Next(0, Roots.Length)];
        var f = new DecoyFactory(ctx, rng, root);

        // Phase 1 — declare every archetype (type + fields + Core + Tick + named methods, no bodies yet).
        var builders = new Action[]
        {
            () => f.LicenseRing(),
            () => f.FeatureTierMatrix(),
            () => f.NativeDongleShim(),
            () => f.UpdateHandshake(),
            () => f.KdfVault(),
            () => f.TelemetryBeacon(),
            () => f.EntitlementStore(),
            // Functional (non-security) subsystems — broaden goal-coverage beyond the licensing/DRM
            // framing so a data-/network-/storage-framed analyst also bites (v2 lesson: decoys only
            // derail an agent whose goal makes the fake names look relevant).
            () => f.SerializationRegistry(),
            () => f.ProtocolRouter(),
            () => f.CacheCoordinator(),
        };

        int archetypes = 0;
        foreach (Action declare in builders)
        {
            if (!ctx.Budget.TryReserve(EstTypeBytes))
            {
                report.Notes.Add("size budget reached; remaining decoy archetypes skipped");
                break;
            }
            declare();
            archetypes++;
        }

        // Phase 2 — wire the interconnected call graph: cross-type edges, typed cross-fields, orchestrator.
        f.Interconnect();
        bool brokerAdded = ctx.Budget.TryReserve(EstTypeBytes) && f.BuildBroker();

        // Phase 3 — real->decoy edges: a bounded set of user methods gain an opaque-guarded dead call
        // into the broker, so the decoys look used by real code. Only if a broker exists.
        int realEdges = 0;
        if (brokerAdded)
            realEdges = WireRealToDecoyEdges(ctx, rng, f.BrokerEntry!);

        report.Count("decoy_types", archetypes + (brokerAdded ? 1 : 0));
        report.Count("decoy_methods", f.MethodCount);
        report.Count("decoy_fields", f.FieldCount);
        report.Count("decoy_pinvokes", f.PInvokeCount);
        report.Count("decoy_cross_edges", f.CrossEdgeCount);
        report.Count("real_to_decoy_edges", realEdges);
        report.EstimatedBytesAdded = (long)(archetypes + (brokerAdded ? 1 : 0)) * EstTypeBytes + realEdges * EstEdgeBytes;
        report.Notes.Add($"decoy namespace root: {root}.* (seeded — our archetype map, not BLA's)");
        report.Notes.Add($"interconnected: {f.CrossEdgeCount} decoy->decoy call edges + typed cross-fields; central {root}.Core.SubsystemBroker hub");
        report.Notes.Add($"{realEdges} real->decoy call edge(s) injected behind an always-true opaque guard (dead code; never executed)");
        report.Notes.Add("multi-domain archetypes: security themes (licensing/dongle/KDF/telemetry) + functional subsystems (serialization/protocol/cache) to broaden analyst-goal coverage — functional set DesignedFor, not yet re-measured vs REA");
    }

    /// <summary>
    /// Prepends to up to <see cref="MaxRealToDecoyEdges"/> real user methods an opaque-false-guarded
    /// call into the decoy broker. The guard <c>(seed | 1) != 0</c> is always true, so the broker call
    /// is dead — identical to P2's proven-safe pattern. State machines are skipped via UserMethods().
    /// </summary>
    private static int WireRealToDecoyEdges(ProtectionContext ctx, SeededPrng rng, MethodDef brokerEntry)
    {
        List<MethodDef> targets = ctx.UserMethods().Where(m => m.Body.Instructions.Count > 0).ToList();
        if (targets.Count == 0) return 0;

        FieldDef seed = EnsureSeedField(ctx, rng);
        int budget = Math.Min(MaxRealToDecoyEdges, targets.Count);
        int edges = 0;
        for (int i = 0; i < targets.Count && edges < budget; i++)
        {
            MethodDef m = targets[i];
            if (!ctx.Budget.TryReserve(EstEdgeBytes)) break;

            IList<Instruction> ins = m.Body.Instructions;
            Instruction firstOriginal = ins[0];
            var injected = new[]
            {
                OpCodes.Ldsfld.ToInstruction(seed),
                OpCodes.Ldc_I4_1.ToInstruction(),
                OpCodes.Or.ToInstruction(),
                OpCodes.Brtrue.ToInstruction(firstOriginal), // always taken → skips the decoy call
                Instruction.CreateLdcI4(unchecked((int)rng.NextUInt32())),
                OpCodes.Call.ToInstruction(brokerEntry),      // dead real->decoy edge REA records
                OpCodes.Pop.ToInstruction(),                  // broker entry returns int
            };
            for (int j = 0; j < injected.Length; j++) ins.Insert(j, injected[j]);
            m.Body.OptimizeMacros();
            m.Body.OptimizeBranches();
            edges++;
        }
        return edges;
    }

    private static FieldDef EnsureSeedField(ProtectionContext ctx, SeededPrng rng)
    {
        var field = new FieldDefUser(rng.NextIdentifier(rng.Next(8, 14)), new FieldSig(ctx.Cor.Int32),
            dnlib.DotNet.FieldAttributes.Assembly | dnlib.DotNet.FieldAttributes.Static);
        ctx.RuntimeType.Fields.Add(field);

        MethodDef cctor = ctx.RuntimeType.FindOrCreateStaticConstructor();
        cctor.Body ??= new CilBody();
        IList<Instruction> cil = cctor.Body.Instructions;
        cil.Insert(0, OpCodes.Stsfld.ToInstruction(field));
        cil.Insert(0, Instruction.CreateLdcI4(unchecked((int)rng.NextUInt32())));
        if (cil.Count == 0 || cil[cil.Count - 1].OpCode.Code != Code.Ret)
            cil.Add(OpCodes.Ret.ToInstruction());
        cctor.Body.OptimizeMacros();
        return field;
    }
}

/// <summary>Builds inert-but-believable, interconnected decoy types with valid, stack-balanced IL.</summary>
internal sealed class DecoyFactory
{
    private readonly ProtectionContext _ctx;
    private readonly SeededPrng _rng;
    private readonly string _root;

    private readonly List<Archetype> _types = new();

    public int MethodCount { get; private set; }
    public int FieldCount { get; private set; }
    public int PInvokeCount { get; private set; }
    public int CrossEdgeCount { get; private set; }
    public MethodDef? BrokerEntry { get; private set; }

    public DecoyFactory(ProtectionContext ctx, SeededPrng rng, string root)
    {
        _ctx = ctx;
        _rng = rng;
        _root = root;
    }

    private TypeSig I4 => _ctx.Cor.Int32;
    private TypeSig U4 => _ctx.Cor.UInt32;
    private TypeSig Bool => _ctx.Cor.Boolean;
    private TypeSig Str => _ctx.Cor.String;
    private TypeSig Void => _ctx.Cor.Void;
    private SZArraySig Bytes => new(_ctx.Cor.Byte);
    private SZArraySig Ints => new(_ctx.Cor.Int32);

    /// <summary>A declared archetype: its type, its <c>Core(int):int</c>, and the named methods +
    /// string pools whose bodies get emitted (with cross edges) in <see cref="Interconnect"/>.</summary>
    private sealed class Archetype
    {
        public required TypeDef Type;
        public required MethodDef Core;
        public FieldDef? Link;                 // typed reference to a sibling archetype (cross-field)
        public readonly List<(MethodDef m, TypeSig ret, string[] strings)> Named = new();
    }

    // ---- archetypes (Phase 1: declare only) ----

    public void LicenseRing()
    {
        var a = NewArchetype("Licensing", "LicenseRing");
        AddField(a.Type, "_ringSeed", I4);
        AddField(a.Type, "_slots", Ints);
        Declare(a, "Validate", Bool, new[] { Str }, new[] { "LIC-RING-3", "signature mismatch", "license expired", "{0}-{1}-{2}-{3}", "perpetual", "node-locked", "grace-period=14d" });
        Declare(a, "RotateRing", Void, Array.Empty<TypeSig>(), new[] { "ring.rotate", "epoch", "HKLM\\Software\\Vertex\\Ring" });
        Declare(a, "ComputeChecksum", U4, new TypeSig[] { Bytes }, new[] { "crc32", "poly=0xEDB88320" });
    }

    public void FeatureTierMatrix()
    {
        var a = NewArchetype("Features", "FeatureTierMatrix");
        AddField(a.Type, "_matrix", Ints);
        AddField(a.Type, "_tierCount", I4);
        Declare(a, "IsFeatureEnabled", Bool, new[] { I4, I4 }, new[] { "Free", "Pro", "Enterprise", "feature.export", "feature.api", "feature.sso", "feature.audit", "feature.quota" });
        Declare(a, "LoadMatrix", Void, Array.Empty<TypeSig>(), new[] { "matrix.bin", "tiers=3", "entitlements.dat" });
    }

    public void NativeDongleShim()
    {
        var a = NewArchetype("Hardware", "NativeDongleShim");
        AddField(a.Type, "_vendorCode", I4);
        AddPInvoke(a.Type, "QueryDongle", I4, new[] { I4 }, "hasp_windows_x64.dll", "hasp_login");
        Declare(a, "IsDonglePresent", Bool, Array.Empty<TypeSig>(), new[] { "SENTINEL HASP", "dongle not detected", "vendor-code", "feature-id=1", "USB\\VID_0529" });
    }

    public void UpdateHandshake()
    {
        var a = NewArchetype("Updates", "UpdateHandshake");
        AddField(a.Type, "_nonce", Bytes);
        Declare(a, "BeginHandshake", Bytes, Array.Empty<TypeSig>(), new[] { "https://updates.internal.example/handshake", "X-Update-Nonce", "channel=stable", "v2", "User-Agent: Vertex/2.3" });
        Declare(a, "VerifyNonce", Bool, new TypeSig[] { Bytes, Bytes }, new[] { "nonce mismatch", "replay", "ts-skew" });
    }

    public void KdfVault()
    {
        var a = NewArchetype("Security", "KdfVault");
        AddField(a.Type, "_salt", Bytes);
        AddField(a.Type, "_rounds", I4);
        Declare(a, "Derive", Bytes, new TypeSig[] { Bytes, I4 }, new[] { "PBKDF2-HMAC-SHA256", "vault.sealed", "AES-256-GCM", "iterations=100000", "kdf.v2" });
        Declare(a, "Unseal", Bytes, new TypeSig[] { Bytes }, new[] { "unseal.failed", "tag mismatch", "nonce-reuse" });
    }

    public void TelemetryBeacon()
    {
        var a = NewArchetype("Diagnostics", "TelemetryBeacon");
        AddField(a.Type, "_endpoint", Str);
        AddField(a.Type, "_queue", Ints);
        Declare(a, "Emit", Void, new[] { I4 }, new[] { "https://telemetry.internal.example/ingest", "evt.license", "evt.feature", "batch=64", "X-Api-Key" });
        Declare(a, "Flush", I4, Array.Empty<TypeSig>(), new[] { "flush.deadline", "retry=3", "backoff=expo" });
    }

    public void EntitlementStore()
    {
        var a = NewArchetype("Licensing", "EntitlementStore");
        AddField(a.Type, "_store", Bytes);
        AddField(a.Type, "_rev", I4);
        Declare(a, "Resolve", Bool, new[] { Str }, new[] { "ent.store.v3", "sku=ENTERPRISE", "seat-count", "offline-grant", "sig=ed25519" });
        Declare(a, "Commit", Void, new[] { I4 }, new[] { "store.commit", "wal.append", "fsync" });
    }

    // ---- functional (non-security) archetypes: broaden analyst-goal coverage (Phase 1: declare only) ----

    public void SerializationRegistry()
    {
        var a = NewArchetype("Data", "SerializationRegistry");
        AddField(a.Type, "_schemaRev", I4);
        AddField(a.Type, "_wireCache", Bytes);
        Declare(a, "Encode", Bytes, new TypeSig[] { Bytes }, new[] { "wire.v4", "msgpack", "schema-id", "field-tag", "varint", "zigzag" });
        Declare(a, "Decode", I4, new TypeSig[] { Bytes }, new[] { "truncated frame", "unknown schema", "crc mismatch", "len-prefix" });
    }

    public void ProtocolRouter()
    {
        var a = NewArchetype("Net", "ProtocolRouter");
        AddField(a.Type, "_routes", Ints);
        Declare(a, "RouteFrame", I4, new[] { I4, I4 }, new[] { "OP_HELLO", "OP_SYNC", "OP_PUSH", "frame too large", "seq-window", "ack-timeout" });
        Declare(a, "Negotiate", Bool, Array.Empty<TypeSig>(), new[] { "proto/3.1", "compression=lz4", "keepalive=30s", "max-inflight=128" });
    }

    public void CacheCoordinator()
    {
        var a = NewArchetype("Storage", "CacheCoordinator");
        AddField(a.Type, "_slots", Ints);
        AddField(a.Type, "_rev", I4);
        Declare(a, "Lookup", Bool, new[] { I4 }, new[] { "lru.evict", "shard=16", "wal.append", "hit-ratio", "cold-miss" });
        Declare(a, "Store", Void, new[] { I4 }, new[] { "fsync", "compaction", "tombstone", "page-size=4096" });
    }

    // ---- Phase 2: interconnect + orchestrate ----

    /// <summary>Emits every archetype's method bodies now that all types exist, wiring decoy->decoy
    /// call edges (into a sibling's <c>Core</c>) and typed cross-field accesses.</summary>
    public void Interconnect()
    {
        if (_types.Count == 0) return;
        for (int i = 0; i < _types.Count; i++)
        {
            Archetype self = _types[i];
            Archetype sibling = _types[(i + 1) % _types.Count];

            // Typed cross-field: a static field of the sibling's type (a believable "link").
            self.Link = new FieldDefUser("_link", new FieldSig(new ClassSig(sibling.Type)),
                dnlib.DotNet.FieldAttributes.Private | dnlib.DotNet.FieldAttributes.Static);
            self.Type.Fields.Add(self.Link);
            FieldCount++;

            foreach ((MethodDef m, TypeSig ret, string[] strings) in self.Named)
                EmitInterconnectedBody(m, ret, strings, self, sibling);
        }
    }

    /// <summary>Builds the central <c>SubsystemBroker</c> hub whose <c>Dispatch</c> calls every
    /// archetype's <c>Core</c> — a high-out-degree node a reader reads as the protection coordinator.
    /// Returns false if nothing to orchestrate.</summary>
    public bool BuildBroker()
    {
        if (_types.Count == 0) return false;
        var t = new TypeDefUser($"{_root}.Core", "SubsystemBroker", _ctx.Cor.Object.TypeDefOrRef)
        {
            Attributes = dnlib.DotNet.TypeAttributes.NotPublic | dnlib.DotNet.TypeAttributes.AutoLayout
                         | dnlib.DotNet.TypeAttributes.AnsiClass | dnlib.DotNet.TypeAttributes.Sealed
                         | dnlib.DotNet.TypeAttributes.BeforeFieldInit,
        };
        _ctx.Module.Types.Add(t);

        var sig = MethodSig.CreateStatic(I4, I4);
        var dispatch = new MethodDefUser("Dispatch", sig, MethodImplAttributes.IL | MethodImplAttributes.Managed,
            dnlib.DotNet.MethodAttributes.Assembly | dnlib.DotNet.MethodAttributes.Static
                | dnlib.DotNet.MethodAttributes.HideBySig);
        var body = new CilBody { InitLocals = true, MaxStack = 8 };
        IList<Instruction> il = body.Instructions;
        il.Add(OpCodes.Ldarg_0.ToInstruction());                 // acc = x
        foreach (Archetype a in _types)
        {
            il.Add(Instruction.CreateLdcI4(unchecked((int)_rng.NextUInt32())));
            il.Add(OpCodes.Call.ToInstruction(a.Core));           // acc ^= a.Core(const)   — cross edge
            il.Add(OpCodes.Xor.ToInstruction());
            CrossEdgeCount++;
        }
        il.Add(OpCodes.Ret.ToInstruction());
        dispatch.Body = body;
        body.OptimizeMacros();
        t.Methods.Add(dispatch);
        MethodCount++;
        BrokerEntry = dispatch;
        return true;
    }

    // ---- construction helpers ----

    private Archetype NewArchetype(string area, string name)
    {
        var t = new TypeDefUser($"{_root}.{area}", name, _ctx.Cor.Object.TypeDefOrRef)
        {
            Attributes = dnlib.DotNet.TypeAttributes.NotPublic | dnlib.DotNet.TypeAttributes.AutoLayout
                         | dnlib.DotNet.TypeAttributes.AnsiClass | dnlib.DotNet.TypeAttributes.Sealed
                         | dnlib.DotNet.TypeAttributes.BeforeFieldInit,
        };
        _ctx.Module.Types.Add(t);
        MethodDef core = AddCore(t);
        var a = new Archetype { Type = t, Core = core };
        _types.Add(a);
        return a;
    }

    private void AddField(TypeDef t, string name, TypeSig type)
    {
        t.Fields.Add(new FieldDefUser(name, new FieldSig(type),
            dnlib.DotNet.FieldAttributes.Private | dnlib.DotNet.FieldAttributes.Static));
        FieldCount++;
    }

    /// <summary>A believable inner helper every archetype calls: <c>static int Core(int)</c>.</summary>
    private MethodDef AddCore(TypeDef t)
    {
        var sig = MethodSig.CreateStatic(I4, I4);
        var m = new MethodDefUser("Core", sig, MethodImplAttributes.IL | MethodImplAttributes.Managed,
            dnlib.DotNet.MethodAttributes.Private | dnlib.DotNet.MethodAttributes.Static
                | dnlib.DotNet.MethodAttributes.HideBySig);
        var body = new CilBody { InitLocals = true, MaxStack = 4 };
        IList<Instruction> il = body.Instructions;
        il.Add(OpCodes.Ldarg_0.ToInstruction());
        il.Add(Instruction.CreateLdcI4(unchecked((int)_rng.NextUInt32())));
        il.Add(OpCodes.Xor.ToInstruction());
        il.Add(Instruction.CreateLdcI4(unchecked((int)_rng.NextUInt32() | 1)));
        il.Add(OpCodes.Mul.ToInstruction());
        il.Add(OpCodes.Ret.ToInstruction());
        m.Body = body;
        body.OptimizeMacros();
        t.Methods.Add(m);
        MethodCount++;
        return m;
    }

    /// <summary>Declares a named method (signature only); its body is emitted in <see cref="Interconnect"/>.</summary>
    private void Declare(Archetype a, string name, TypeSig ret, TypeSig[] ps, string[] strings)
    {
        MethodSig sig = ps.Length == 0 ? MethodSig.CreateStatic(ret) : MethodSig.CreateStatic(ret, ps);
        var m = new MethodDefUser(name, sig, MethodImplAttributes.IL | MethodImplAttributes.Managed,
            dnlib.DotNet.MethodAttributes.Assembly | dnlib.DotNet.MethodAttributes.Static
                | dnlib.DotNet.MethodAttributes.HideBySig);
        a.Type.Methods.Add(m);
        a.Named.Add((m, ret, strings));
        MethodCount++;
    }

    private void AddPInvoke(TypeDef t, string name, TypeSig ret, TypeSig[] ps, string dll, string entry)
    {
        var modref = new ModuleRefUser(_ctx.Module, dll);
        MethodSig sig = MethodSig.CreateStatic(ret, ps);
        var m = new MethodDefUser(name, sig, MethodImplAttributes.PreserveSig,
            dnlib.DotNet.MethodAttributes.Private | dnlib.DotNet.MethodAttributes.Static
                | dnlib.DotNet.MethodAttributes.HideBySig | dnlib.DotNet.MethodAttributes.PinvokeImpl)
        {
            ImplMap = new ImplMapUser(modref, entry,
                PInvokeAttributes.CallConvWinapi | PInvokeAttributes.CharSetAnsi | PInvokeAttributes.SupportsLastError),
        };
        t.Methods.Add(m); // no body — the P/Invoke declaration itself is the decoy; never invoked
        PInvokeCount++;
    }

    /// <summary>Emits a valid, stack-balanced, inert body that references believable strings, calls a
    /// sibling archetype's <c>Core</c> (decoy->decoy edge), and touches the typed cross-field.</summary>
    private void EmitInterconnectedBody(MethodDef m, TypeSig ret, string[] strings, Archetype self, Archetype sibling)
    {
        var body = new CilBody { InitLocals = true, MaxStack = 8 };
        IList<Instruction> il = body.Instructions;

        int stmts = _rng.Next(2, 5);
        for (int i = 0; i < stmts; i++)
        {
            il.Add(OpCodes.Ldstr.ToInstruction(strings[_rng.Next(0, strings.Length)]));
            il.Add(OpCodes.Pop.ToInstruction());
        }

        // Typed cross-field access (ldsfld sibling-typed field; discard) — a field-access edge for REA.
        if (self.Link is not null)
        {
            il.Add(OpCodes.Ldsfld.ToInstruction(self.Link));
            il.Add(OpCodes.Pop.ToInstruction());
        }

        // Decoy->decoy call edge: call the sibling's Core(int) and discard its result.
        il.Add(Instruction.CreateLdcI4(unchecked((int)_rng.NextUInt32())));
        il.Add(OpCodes.Call.ToInstruction(sibling.Core));
        il.Add(OpCodes.Pop.ToInstruction());
        CrossEdgeCount++;

        EmitReturnValue(il, ret, self.Core);
        il.Add(OpCodes.Ret.ToInstruction());
        m.Body = body;
        body.OptimizeMacros();
    }

    private void EmitReturnValue(IList<Instruction> il, TypeSig ret, MethodDef core)
    {
        switch (ret.ElementType)
        {
            case ElementType.Void:
                return;
            case ElementType.Boolean:
                EmitInt(il, core);
                il.Add(OpCodes.Ldc_I4_0.ToInstruction());
                il.Add(OpCodes.Cgt_Un.ToInstruction());
                return;
            case ElementType.I4:
            case ElementType.U4:
                EmitInt(il, core);
                return;
            case ElementType.String:
                il.Add(OpCodes.Ldstr.ToInstruction("ok"));
                return;
            case ElementType.SZArray:
                il.Add(Instruction.CreateLdcI4(_rng.Next(8, 33)));
                il.Add(OpCodes.Newarr.ToInstruction(_ctx.Cor.Byte.ToTypeDefOrRef()));
                return;
            default:
                il.Add(OpCodes.Ldnull.ToInstruction());
                return;
        }
    }

    private void EmitInt(IList<Instruction> il, MethodDef core)
    {
        il.Add(Instruction.CreateLdcI4(unchecked((int)_rng.NextUInt32())));
        il.Add(OpCodes.Call.ToInstruction(core)); // believable call edge into the archetype's own Core
    }
}
