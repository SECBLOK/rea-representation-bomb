using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Passes;

/// <summary>
/// P9 — Representation bomb (GATED, never on by default). Plants N dead static fields and N dead
/// static methods across a handful of <b>stealth decoy types</b>; every injected method body reads
/// <b>all</b> N fields (<c>ldsfld</c>) and calls <b>all</b> N methods (<c>call</c>). That is
/// <b>2·N² cross-reference edges</b> that rea must materialise into its managed representation.
///
/// ✅ MEASURED analysis-denial-by-exhaustion vs real rea (rea@6.7.0 local and 6.9.0 pod, 2026-11-16).
/// The quadratic edge set crosses rea's <b>67,108,864-byte (64 MiB) representation budget</b>, so rea
/// admits <b>ZERO methods / fields</b> — the managed member inventory is denied. Two measured surface
/// forms of the same budget lever: rea 6.7.0 → <c>coverage.state="unavailable"</c> / resource-limit,
/// 0 types; rea 6.9.0 → <c>coverage.state="partial"</c> / resource-limit, type NAMES listed but
/// <b>0 methods</b>. On FileHound: −99.96% tokens (6.7.0), −98.6% (6.9.0). The measured cliff is
/// ~218k–238k edges on FileHound.Core.dll; all default N here clear it with margin.
///
/// A SECOND measured denial mechanism beside P6: P6 breaks the metadata <i>parser</i> (duplicate
/// stream → <c>malformed</c>), P9 exhausts the representation <i>budget</i> (→ <c>unavailable</c>/
/// <c>partial</c> with 0 members). <b>For a clean refusal on every rea version (0 types, no leaked
/// names), stack P6: <c>--passes …,P6,P9</c></b> — P6's parser-break reports <c>malformed</c> with 0
/// types on BOTH 6.7.0 and 6.9.0 (measured), while P9 guarantees exhaustion even if the budget is
/// raised. Defense in depth: rea must tolerate the stream construction AND raise its budget to analyse.
///
/// <para><b>Open-source hardening — the per-build SEED is the secret (Kerckhoffs), not the algorithm.</b>
/// Everything that could be a fixed strip signature is randomized per build off the project seed (which
/// defaults to a cryptographically-random value — see <c>SeedPolicy</c>): (a) decoy names are compound,
/// counter-free, drawn from wide pools across 2..4 namespace roots; (b) per-type member counts are
/// uneven (no uniform-16 cluster); (c) bodies use k=3..6 per-build SHAPES (varied order/interleave/junk)
/// so the identical-body clone tell is broken while methods sharing a shape still dedup to one RVA; and
/// (d) a seeded subset of decoy bodies reads real static members (ldsfld/ldftn) so the subgraph is not a
/// cleanly-disconnected clique. Two builds of the same input therefore share no static strip signature.</para>
///
/// <para><b>Reachability anchor (vs a cheap mark-sweep).</b> A bounded, seeded set of real user methods
/// gains an opaque-false-guarded dead call into the decoy clique (reuses P2/P4's proven pattern), giving
/// it in-edges from rooted code so an ILLink-style / dnlib reachability sweep cannot prune it as a
/// zero-in-edge dead SCC. The guard is always true → the call is never executed.</para>
///
/// Runtime safety: every injected decoy method is unreachable — nothing in the real program's live path
/// reaches one (the anchor edge is dead), so the CLR never JITs a decoy (proven by the
/// runtime-equivalence gate and the P9HardeningTests). Bodies sharing a shape are byte-identical, so
/// dnlib shares one RVA per shape: on-disk growth is ~O(k·N) (tens of KB) while rea's expansion is O(N²).
/// All growth is vetoed by <see cref="SizeBudget"/>.
///
/// SAFETY (why gated) + HONEST LIMIT: the denial depends on rea's budget being the default 64 MiB (a
/// per-command, user-raisable ceiling), and a large dead-member set is still unusual. The hardening
/// defeats signature/statistical strippers (Tier A) and a cheap reachability sweep (Tier B); it does
/// NOT defeat a trace-based or constant-folding stripper (Tier C) — that would require genuinely-running
/// side-effecting decoys, which is declined to keep runtime identical. Economic deterrent (buys cost/
/// time), not impossibility. Off by default; enable with <c>--passes P9</c> and runtime-test per target.
/// Re-check the rea exhaustion with <c>scripts/rea-p9-exhaustion-gate.ps1</c> (or <c>.sh</c>).
/// </summary>
public sealed class RepresentationBombPass : IProtectionPass
{
    public string Id => "P9";
    public string Name => "Representation bomb (quadratic cross-reference — measured rea exhaustion)";
    public SafetyClass Safety => SafetyClass.Gated;
    public EvidenceStatus Status => EvidenceStatus.Verified;
    public bool DefaultFor(Intensity intensity) => false; // opt-in only (--passes P9)

    // N dead methods + N dead fields → 2·N² edges. Defaults clear the MEASURED ~238k-edge cliff with
    // margin (2·N²): Stealth 384 → 294,912 · Balanced 512 → 524,288 · Maximum 768 → 1,179,648.
    private const int EstBytesPerMember = 48;       // methoddef+fielddef+param rows + shared-body share

    // Seeded "sharded subsystem" vocabulary — reads as a real indexer/cache component (fitting for a
    // file-search app) rather than an obvious dead-method bank. Compound names are drawn from these
    // pools so the combinatorial space (thousands of combos) dwarfs N, breaking any fixed name
    // fingerprint; no sequential counter is ever appended (open-source hardening).
    private static readonly string[] Roots =
        { "Helios", "Aurora", "Meridian", "Nimbus", "Keystone", "Solstice", "Ardent", "Pinnacle",
          "Vertex", "Cobalt", "Zephyr", "Halcyon", "Lattice", "Beacon", "Cinder", "Quanta" };
    private static readonly string[] Areas =
        { "Indexing", "Caching", "Storage", "Partitioning", "Scheduling", "Pipeline", "Query", "Sync",
          "Buffers", "Segments", "Routing", "Compaction", "Journaling", "Replication", "Coordination", "Paging" };
    private static readonly string[] TypeNouns =
        { "Shard", "Partition", "Segment", "Bucket", "Lane", "Slot", "Page", "Block", "Region", "Chunk",
          "Node", "Frame", "Cursor", "Index" };
    private static readonly string[] TypeSuffixes =
        { "Coordinator", "Table", "Cache", "Registry", "Dispatcher", "Allocator", "Store", "Manager",
          "Broker", "Pool", "Map", "Catalog", "Tracker", "Pipeline" };
    private static readonly string[] FieldNouns =
        { "shard", "partition", "segment", "bucket", "slot", "lane", "page", "block", "region", "chunk",
          "cursor", "offset", "epoch", "revision" };
    private static readonly string[] MethodVerbs =
        { "Resolve", "Flush", "Compact", "Rebuild", "Advance", "Scan", "Reserve", "Drain", "Rotate", "Seal",
          "Map", "Sweep", "Merge", "Split", "Promote", "Evict" };
    private static readonly string[] MethodNouns =
        { "Partition", "Shard", "Segment", "Bucket", "Lane", "Slot", "Page", "Block", "Region", "Chunk",
          "Cursor", "Index", "Entry", "Record" };

    private static int DesiredN(Intensity intensity) => intensity switch
    {
        Intensity.Maximum => 768,
        Intensity.Balanced => 512,
        _ => 384, // Stealth
    };

    public void Run(ProtectionContext ctx, PassReport report)
    {
        SeededPrng rng = ctx.Prng.Fork("p9-repbomb");

        // Pick the largest N that fits the size budget (never exceed it); defaults already fit the
        // 512 KiB floor by a wide margin because the shared body makes on-disk cost ~O(N).
        int desired = DesiredN(ctx.Options.Intensity);
        long affordable = ctx.Budget.RemainingBytes / EstBytesPerMember;
        int n = (int)System.Math.Min(desired, System.Math.Max(0, affordable));
        if (n < 2) { report.Notes.Add("P9 skipped: size budget too small to plant a representation bomb."); return; }
        int bodyShapeCount = rng.Next(3, 7);                       // k = 3..6 per-build body shapes
        long est = (long)n * EstBytesPerMember + (long)bodyShapeCount * 12 * n; // + k shared ~O(N) bodies
        if (!ctx.Budget.TryReserve(est)) { report.Notes.Add("P9 skipped: size budget reservation failed."); return; }

        // Snapshot real static members BEFORE injecting decoys — cross-boundary targets so the decoy
        // subgraph is not a cleanly-disconnected clique (local stealth). Referenced only from never-run
        // decoy bodies, so ldsfld/ldftn of any real static member is safe regardless of accessibility.
        var realFields = new List<FieldDef>();
        var realMethods = new List<MethodDef>();
        foreach (TypeDef rt in ctx.Module.GetTypes())
        {
            foreach (FieldDef fd in rt.Fields)
                if (fd.IsStatic && !fd.IsLiteral && realFields.Count < 8) realFields.Add(fd);
            foreach (MethodDef md in rt.Methods)
                if (md.IsStatic && !md.IsAbstract && !md.IsPinvokeImpl && !md.HasGenericParameters
                    && md.Name != ".cctor" && realMethods.Count < 8) realMethods.Add(md);
        }
        // Snapshot real user methods (with bodies, no state machines) as reachability-anchor targets,
        // BEFORE injecting decoys so a decoy method is never chosen as an anchor site.
        var anchorTargets = new List<MethodDef>(ctx.UserMethods());

        // Stealth decoy types with believable, compound, counter-free names drawn from wide pools and
        // spread across 2..4 seeded namespace roots (collective-regularity broken — no single root/bank).
        var namer = new UniqueNamer(rng);

        // Seeded type count → uneven member distribution (avg ~8..40 members/type); random homes so no
        // type has a fixed, uniform member count (removes the uniform-count cluster tell).
        int typeCount = System.Math.Max(2, System.Math.Min(n / 2, rng.Next(n / 40 + 1, n / 8 + 2)));
        int[] fieldHome = new int[n];
        int[] methodHome = new int[n];
        for (int i = 0; i < n; i++) { fieldHome[i] = rng.Next(0, typeCount); methodHome[i] = rng.Next(0, typeCount); }

        // Materialise only type indices that actually received >= 1 member (no empty decoy types),
        // remapped to a dense 0..realTypeCount-1 range.
        var usedIdx = new SortedSet<int>();
        for (int i = 0; i < n; i++) { usedIdx.Add(fieldHome[i]); usedIdx.Add(methodHome[i]); }
        var indexRemap = new Dictionary<int, int>();
        foreach (int v in usedIdx) indexRemap[v] = indexRemap.Count;
        int realTypeCount = usedIdx.Count;

        int rootCount = System.Math.Min(Roots.Length, rng.Next(2, 5));
        var rootPool = new List<string>();
        var seenRoots = new HashSet<string>();
        while (rootPool.Count < rootCount)
        {
            string r = Roots[rng.Next(0, Roots.Length)];
            if (seenRoots.Add(r)) rootPool.Add(r);
        }
        var decoyTypes = new TypeDef[realTypeCount];
        for (int t = 0; t < realTypeCount; t++)
        {
            // First rootPool.Count types get one distinct root each (guarantees every root is used);
            // the rest draw a random root from the pool.
            string rootNs = t < rootPool.Count ? rootPool[t] : rootPool[rng.Next(0, rootPool.Count)];
            string ns = rootNs + "." + Areas[rng.Next(0, Areas.Length)];
            string name = namer.Draw(TypeNouns, TypeSuffixes); // compound, unique, counter-free
            var td = new TypeDefUser(ns, name, ctx.Cor.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.NotPublic | TypeAttributes.AutoLayout | TypeAttributes.AnsiClass
                             | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit,
            };
            ctx.Module.Types.Add(td);
            decoyTypes[t] = td;
        }

        // N dead static int fields + N dead static void methods, placed in their seeded home types
        // (uneven), with unique compound names.
        var fields = new FieldDef[n];
        var methods = new MethodDef[n];
        for (int i = 0; i < n; i++)
        {
            string fn = namer.Draw(FieldNouns, FieldNouns, FieldNouns, prefix: "_");
            var f = new FieldDefUser(fn, new FieldSig(ctx.Cor.Int32),
                FieldAttributes.Private | FieldAttributes.Static);
            decoyTypes[indexRemap[fieldHome[i]]].Fields.Add(f);
            fields[i] = f;

            string mn = namer.Draw(MethodVerbs, MethodNouns, MethodNouns);
            var m = new MethodDefUser(mn, MethodSig.CreateStatic(ctx.Cor.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig);
            decoyTypes[indexRemap[methodHome[i]]].Methods.Add(m);
            methods[i] = m;
        }

        // Spread of members per decoy type (0 = uniform, >= 1 = uneven).
        int[] memberCounts = new int[realTypeCount];
        for (int i = 0; i < n; i++) { memberCounts[indexRemap[fieldHome[i]]]++; memberCounts[indexRemap[methodHome[i]]]++; }
        int minMembers = int.MaxValue, maxMembers = 0;
        foreach (int c in memberCounts) { if (c < minMembers) minMembers = c; if (c > maxMembers) maxMembers = c; }

        // Per-build body polymorphism: k seeded body SHAPES, each still referencing ALL N fields
        // (ldsfld) and ALL N methods (call) — same 2·N² edge set — but in a different order / interleave
        // / junk pattern. Methods sharing a shape have byte-identical bodies (dnlib shares one RVA per
        // shape → on-disk O(k·N)); across builds the shapes differ, so there is no fixed body signature.
        var shapes = new BodyShape[bodyShapeCount];
        for (int s = 0; s < bodyShapeCount; s++)
            shapes[s] = new BodyShape(rng.NextBool(), rng.NextBool(), new[] { 0, 5, 7, 11 }[rng.Next(0, 4)]);
        // Guarantee >= 2 distinct shapes even if the RNG drew duplicates.
        var distinctShapes = new HashSet<BodyShape>(shapes);
        if (distinctShapes.Count < 2)
        {
            shapes[0] = shapes[0] with { Interleave = !shapes[0].Interleave };
            distinctShapes = new HashSet<BodyShape>(shapes);
        }
        // Per-shape cross-boundary references (decoy -> real members): ~half the shapes carry 1..3 real
        // static refs (shape 0 always carries when a pool exists) so the decoy subgraph has boundary
        // edges (local stealth) rather than a cleanly-disconnected clique.
        var boundaryUsed = new HashSet<IMemberRef>();
        var extraF = new FieldDef[bodyShapeCount][];
        var extraM = new MethodDef[bodyShapeCount][];
        bool havePool = realFields.Count + realMethods.Count > 0;
        for (int s = 0; s < bodyShapeCount; s++)
        {
            bool carry = havePool && (s == 0 || rng.NextBool());
            if (!carry) { extraF[s] = System.Array.Empty<FieldDef>(); extraM[s] = System.Array.Empty<MethodDef>(); continue; }
            int r = rng.Next(1, 4);
            var fList = new List<FieldDef>();
            var mList = new List<MethodDef>();
            for (int q = 0; q < r; q++)
            {
                if (realFields.Count > 0 && (realMethods.Count == 0 || rng.NextBool()))
                { FieldDef fd = realFields[rng.Next(0, realFields.Count)]; fList.Add(fd); boundaryUsed.Add(fd); }
                else if (realMethods.Count > 0)
                { MethodDef md = realMethods[rng.Next(0, realMethods.Count)]; mList.Add(md); boundaryUsed.Add(md); }
            }
            extraF[s] = fList.ToArray();
            extraM[s] = mList.ToArray();
        }

        // First k methods use shapes[0..k-1] (every shape present); the rest draw a random shape.
        for (int i = 0; i < n; i++)
        {
            int sIdx = i < bodyShapeCount ? i : rng.Next(0, bodyShapeCount);
            methods[i].Body = BuildBombBody(fields, methods, shapes[sIdx], extraF[sIdx], extraM[sIdx]);
        }

        // Reachability anchor: give the decoy clique an in-edge from real rooted code (reuses P2/P4's
        // opaque-false-guarded dead-call pattern), so a cheap reachability mark-sweep cannot prune it.
        // The guard is always true → the call is never executed → runtime is unchanged. Rooting any one
        // decoy method roots the whole clique (every decoy method calls all N).
        int anchorEdges = WireAnchorEdges(ctx, rng, methods[rng.Next(0, methods.Length)], anchorTargets);

        long edges = 2L * n * n;
        report.Count("decoy_types", realTypeCount);
        report.Count("decoy_namespace_roots", rootPool.Count);
        report.Count("decoy_members_spread", maxMembers - minMembers);
        report.Count("bomb_fields", n);
        report.Count("bomb_methods", n);
        report.Count("cross_ref_edges", edges);
        report.Count("body_shapes", distinctShapes.Count);
        report.Count("cross_boundary_refs", boundaryUsed.Count);
        report.Count("reach_anchor_edges", anchorEdges);
        report.EstimatedBytesAdded = est;
        report.Notes.Add($"planted {n} dead fields + {n} dead methods across {typeCount} stealth decoy types "
            + $"(seeded compound names across {rootPool.Count} namespace roots) → {edges:N0} cross-reference edges (ldsfld + call). "
            + "MEASURED (rea@6.7.0 & 6.9.0): the quadratic edge set crosses rea's 67,108,864-byte representation "
            + "budget, so inspect-managed-members admits ZERO methods — denial by exhaustion (exit 0, not a crash). "
            + "Cliff ≈218k–238k edges on FileHound.Core.dll.");
        report.Notes.Add("Runtime-safe: all injected methods are unreachable (never JITed); bodies are byte-identical "
            + "so dnlib shares one body RVA (on-disk ~O(N), rea expansion O(N²)). The .NET CLR loads and runs the "
            + "assembly identically — proven by runtime-equivalence.");
        report.Notes.Add("SECOND measured denial beside P6 (P6=parser-break→malformed; P9=budget-exhaustion). For a "
            + "CLEAN refusal with 0 types on every rea version (6.7.0 unavailable, 6.9.0 leaks type names), stack P6: "
            + "'--passes …,P6,P9' (P6 reports malformed/0-types on both; P9 holds even if the budget is raised). GATED: "
            + "rea's 64 MiB budget is user-raisable; re-check with scripts/rea-p9-exhaustion-gate.ps1 / .sh.");
    }

    /// <summary>One per-build body variation: phase order, interleave, and nop-junk cadence. Distinct
    /// shape values serialize to distinct IL byte sequences (distinct RVAs); the referenced field/method
    /// set is identical, so the 2·N² edge set is unchanged.</summary>
    private readonly record struct BodyShape(bool CallsFirst, bool Interleave, int JunkEvery);

    /// <summary>Builds one bomb body for a given shape. Every shape references ALL N fields (ldsfld+pop)
    /// and ALL N methods (call) — the 2·N² edge set is identical across shapes — but the order/interleave
    /// and seeded nop junk differ. Stack-neutral (MaxStack 1); unreachable, so never JITed.</summary>
    private static CilBody BuildBombBody(FieldDef[] fields, MethodDef[] methods, BodyShape shape,
        FieldDef[] extraFieldReads, MethodDef[] extraMethodRefs)
    {
        var body = new CilBody { InitLocals = false, MaxStack = 1 };
        IList<Instruction> il = body.Instructions;
        int since = 0;
        void Junk() { if (shape.JunkEvery > 0 && ++since >= shape.JunkEvery) { il.Add(OpCodes.Nop.ToInstruction()); since = 0; } }

        if (shape.Interleave)
        {
            for (int j = 0; j < fields.Length; j++)
            {
                if (shape.CallsFirst)
                {
                    il.Add(Instruction.Create(OpCodes.Call, methods[j]));
                    il.Add(Instruction.Create(OpCodes.Ldsfld, fields[j]));
                    il.Add(OpCodes.Pop.ToInstruction());
                }
                else
                {
                    il.Add(Instruction.Create(OpCodes.Ldsfld, fields[j]));
                    il.Add(OpCodes.Pop.ToInstruction());
                    il.Add(Instruction.Create(OpCodes.Call, methods[j]));
                }
                Junk();
            }
        }
        else if (shape.CallsFirst)
        {
            for (int j = 0; j < methods.Length; j++) { il.Add(Instruction.Create(OpCodes.Call, methods[j])); Junk(); }
            for (int j = 0; j < fields.Length; j++) { il.Add(Instruction.Create(OpCodes.Ldsfld, fields[j])); il.Add(OpCodes.Pop.ToInstruction()); Junk(); }
        }
        else
        {
            for (int j = 0; j < fields.Length; j++) { il.Add(Instruction.Create(OpCodes.Ldsfld, fields[j])); il.Add(OpCodes.Pop.ToInstruction()); Junk(); }
            for (int j = 0; j < methods.Length; j++) { il.Add(Instruction.Create(OpCodes.Call, methods[j])); Junk(); }
        }

        // Cross-boundary references (decoy -> real), appended before ret. Never executed (unreachable),
        // so ldsfld/ldftn of any real static member is safe regardless of its accessibility.
        foreach (FieldDef fd in extraFieldReads) { il.Add(Instruction.Create(OpCodes.Ldsfld, fd)); il.Add(OpCodes.Pop.ToInstruction()); }
        foreach (MethodDef md in extraMethodRefs) { il.Add(Instruction.Create(OpCodes.Ldftn, md)); il.Add(OpCodes.Pop.ToInstruction()); }

        il.Add(OpCodes.Ret.ToInstruction());
        return body;
    }

    /// <summary>Internal static guard field initialised to a seeded value in the runtime type's cctor
    /// (same pattern as P2/P4). The opaque predicate <c>(guard | 1) != 0</c> is always true.</summary>
    private static FieldDef EnsureGuardField(ProtectionContext ctx, SeededPrng rng)
    {
        var field = new FieldDefUser(rng.NextIdentifier(rng.Next(8, 14)), new FieldSig(ctx.Cor.Int32),
            FieldAttributes.Assembly | FieldAttributes.Static);
        ctx.RuntimeType.Fields.Add(field);
        MethodDef cctor = ctx.RuntimeType.FindOrCreateStaticConstructor();
        cctor.Body ??= new CilBody();
        IList<Instruction> cil = cctor.Body.Instructions;
        cil.Insert(0, OpCodes.Stsfld.ToInstruction(field));
        cil.Insert(0, Instruction.CreateLdcI4(unchecked((int)rng.NextUInt32())));
        if (cil.Count == 0 || cil[cil.Count - 1].OpCode.Code != Code.Ret) cil.Add(OpCodes.Ret.ToInstruction());
        cctor.Body.OptimizeMacros();
        return field;
    }

    /// <summary>Prepends to a bounded, seeded set of real user methods an opaque-false-guarded dead call
    /// into the decoy entry (guard <c>(guard | 1) != 0</c> is always true → brtrue always skips the call).
    /// Gives the clique in-edges from rooted code; identical in spirit to P2 and P4.WireRealToDecoyEdges.
    /// The entry is static void()/0-arg, so no stack cleanup is needed. Never executed → runtime unchanged.</summary>
    private static int WireAnchorEdges(ProtectionContext ctx, SeededPrng rng, MethodDef entry, List<MethodDef> targets)
    {
        if (targets.Count == 0) return 0;
        FieldDef guard = EnsureGuardField(ctx, rng);
        int budget = System.Math.Min(rng.Next(1, 9), targets.Count); // 1..8 anchor sites
        int edges = 0;
        for (int i = 0; i < targets.Count && edges < budget; i++)
        {
            IList<Instruction> ins = targets[i].Body.Instructions;
            if (ins.Count == 0) continue;
            Instruction firstOriginal = ins[0];
            var injected = new[]
            {
                OpCodes.Ldsfld.ToInstruction(guard),
                OpCodes.Ldc_I4_1.ToInstruction(),
                OpCodes.Or.ToInstruction(),
                OpCodes.Brtrue.ToInstruction(firstOriginal), // always taken → skips the decoy call
                OpCodes.Call.ToInstruction(entry),            // dead real->decoy edge (void, no args)
            };
            for (int j = 0; j < injected.Length; j++) ins.Insert(j, injected[j]);
            targets[i].Body.OptimizeMacros();
            targets[i].Body.OptimizeBranches();
            edges++;
        }
        return edges;
    }

    /// <summary>Draws unique, counter-free compound names from token pools (seeded). The combinatorial
    /// space dwarfs the max N, so collisions are rare; on a rare collision it draws again, and only as a
    /// last resort appends seeded letters (still non-sequential — never a <c>...000</c> counter tell).</summary>
    private sealed class UniqueNamer
    {
        private readonly SeededPrng _rng;
        private readonly HashSet<string> _used = new();
        private static readonly char[] Letters = "abcdefghijklmnopqrstuvwxyz".ToCharArray();

        public UniqueNamer(SeededPrng rng) => _rng = rng;

        public string Draw(string[] a, string[] b, string[]? c = null, string prefix = "")
        {
            for (int attempt = 0; attempt < 64; attempt++)
            {
                string name = prefix + a[_rng.Next(0, a.Length)] + b[_rng.Next(0, b.Length)]
                              + (c is null ? "" : c[_rng.Next(0, c.Length)]);
                if (_used.Add(name)) return name;
            }
            string fallback = prefix + a[_rng.Next(0, a.Length)] + b[_rng.Next(0, b.Length)]
                              + Letters[_rng.Next(0, Letters.Length)] + Letters[_rng.Next(0, Letters.Length)];
            while (!_used.Add(fallback)) fallback += Letters[_rng.Next(0, Letters.Length)];
            return fallback;
        }
    }
}
