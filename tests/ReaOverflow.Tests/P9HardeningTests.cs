using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using ReaOverflow.Core.Passes;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Report;
using Xunit;

namespace ReaOverflow.Tests;

public class P9HardeningTests
{
    private static byte[] Sample() => File.ReadAllBytes(SampleLocator.HelloTargetDll());

    private static (ProtectionReport report, byte[] prot) Apply(ulong seed) =>
        Protector.ProtectToBytes(Sample(), new ProtectionOptions
        {
            Intensity = Intensity.Maximum,
            Seed = seed,
            EnabledPasses = new System.Collections.Generic.HashSet<string> { "P9" },
        }, new[] { new RepresentationBombPass() });

    [Fact]
    public void DecoyNames_AreNonSequential_AndNamespaceRootsAreDiversified()
    {
        var (report, prot) = Apply(seed: 0xA11CE);
        PassReport pr = report.Passes[0];

        // At least two distinct namespace roots (collective-regularity broken).
        Assert.True(pr.Counters["decoy_namespace_roots"] >= 2,
            "decoys should spread across >=2 namespace roots");

        using var mod = ModuleDefMD.Load(prot);
        // Among injected static void parameterless methods, no name ends in a >=2-digit run
        // (the old sequential tell), and names are compound words (len >= 8, mixed case).
        var decoyMethods = mod.GetTypes()
            .SelectMany(t => t.Methods)
            .Where(m => m.IsStatic && m.HasBody && m.MethodSig.Params.Count == 0
                        && m.MethodSig.RetType.ElementType == dnlib.DotNet.ElementType.Void
                        && m.Name.String.Length >= 8 && char.IsUpper(m.Name.String[0]))
            .ToList();
        Assert.NotEmpty(decoyMethods);
        Assert.DoesNotContain(decoyMethods, m => Regex.IsMatch(m.Name.String, @"\d{2,}$"));
    }

    [Fact]
    public void DifferentSeeds_ProduceDifferentBytes()
    {
        var (_, a) = Apply(seed: 0x1111);
        var (_, b) = Apply(seed: 0x2222);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void PerTypeMemberCounts_AreNotUniform()
    {
        // The pass knows exactly which types are decoys, so it reports the spread (max-min members
        // per decoy type). Uniform distribution => spread 0; uneven distribution => spread >= 1.
        var (report, _) = Apply(seed: 0xA11CE);
        PassReport pr = report.Passes[0];
        Assert.True(pr.Counters["decoy_members_spread"] >= 1,
            "per-type member counts should vary (max-min >= 1), not be uniform");
    }

    [Fact]
    public void BodyShapes_YieldAtLeastTwoDistinctBodyHashes_ButStaySmall()
    {
        var (report, prot) = Apply(seed: 0xA11CE);
        PassReport pr = report.Passes[0];
        Assert.True(pr.Counters["body_shapes"] >= 2, "expected >=2 body shapes");
        Assert.True(report.GrowthBytes < 1_000_000, $"growth {report.GrowthBytes} too large");

        using var mod = ModuleDefMD.Load(prot);
        // Hash the IL opcode stream of injected static void() methods; expect >=2 distinct hashes.
        var hashes = new System.Collections.Generic.HashSet<string>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                if (m.IsStatic && m.HasBody && m.MethodSig.Params.Count == 0
                    && m.MethodSig.RetType.ElementType == dnlib.DotNet.ElementType.Void
                    && m.Body.Instructions.Count > 10)
                    hashes.Add(string.Join(",", m.Body.Instructions.Select(i => i.OpCode.Code.ToString())));
        Assert.True(hashes.Count >= 2, "expected >=2 distinct decoy body shapes");
    }

    [Fact]
    public void CrossBoundaryRefs_WireDecoysToRealMembers()
    {
        var (report, _) = Apply(seed: 0xA11CE);
        PassReport pr = report.Passes[0];
        Assert.True(pr.Counters.ContainsKey("cross_boundary_refs"), "counter must exist");
        // HelloTarget has real static methods, so decoys should reference >=1 to avoid an isolated clique.
        Assert.True(pr.Counters["cross_boundary_refs"] >= 1,
            "decoys should reference >=1 real member to avoid an isolated clique");
    }

    [Fact]
    public void ReachabilityAnchor_RealMethodCallsADecoy_AndRuntimeUnchanged()
    {
        string baseline = AssemblyRunner.RunToString(Sample());
        var (report, prot) = Apply(seed: 0xA11CE);
        PassReport pr = report.Passes[0];
        Assert.True(pr.Counters["reach_anchor_edges"] >= 1, "expected >=1 real->decoy anchor edge");

        using var mod = ModuleDefMD.Load(prot);
        // Decoy methods: injected static void(), believable names, large body (references all N).
        var decoy = mod.GetTypes().SelectMany(t => t.Methods)
            .Where(m => m.IsStatic && m.HasBody && m.MethodSig.Params.Count == 0
                        && m.MethodSig.RetType.ElementType == dnlib.DotNet.ElementType.Void
                        && m.Body.Instructions.Count > 10)
            .ToHashSet();
        // A rooted (non-decoy) method should contain a call to one of them (an in-edge from real code).
        bool anchored = mod.GetTypes().SelectMany(t => t.Methods)
            .Where(m => m.HasBody && !decoy.Contains(m))
            .Any(m => m.Body.Instructions.Any(i => i.Operand is MethodDef md && decoy.Contains(md)));
        Assert.True(anchored, "a rooted (non-decoy) method should call into the decoy clique");

        // Runtime identical: the guarded edge is always skipped.
        Assert.Equal(baseline, AssemblyRunner.RunToString(prot));
    }
}
