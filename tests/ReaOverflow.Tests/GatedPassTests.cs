using System.IO;
using ReaOverflow.Core.Analysis;
using ReaOverflow.Core.Passes;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Report;
using Xunit;

namespace ReaOverflow.Tests;

public class GatedPassTests
{
    private static byte[] Sample() => File.ReadAllBytes(SampleLocator.HelloTargetDll());

    private static (ProtectionReport, byte[]) Apply(IProtectionPass pass, ulong seed = 0xA11CE,
        RawMetadataVariant variant = RawMetadataVariant.DuplicateStream)
    {
        // Gated passes are off by default, so explicitly enable the one under test.
        var options = new ProtectionOptions
        {
            Intensity = Intensity.Maximum,
            Seed = seed,
            EnabledPasses = new System.Collections.Generic.HashSet<string> { pass.Id },
            RawMetadataVariant = variant,
        };
        return Protector.ProtectToBytes(Sample(), options, new[] { pass });
    }

    [Theory]
    [InlineData(RawMetadataVariant.DuplicateStream, "duplicate metadata stream")]
    [InlineData(RawMetadataVariant.ManyStreams, "> rea's admitted 64")]
    [InlineData(RawMetadataVariant.NonPrintableStreamName, "non-printable")]
    public void P6_RawMetadata_EachVariant_DeniesReaInventory_ButLoadsAndReparsesHere(
        RawMetadataVariant variant, string reasonFragment)
    {
        string baseline = AssemblyRunner.RunToString(Sample());
        (ProtectionReport report, byte[] prot) = Apply(new RawMetadataPass(), variant: variant);

        // At least one metadata stream was added; it is not the retired #JTD marker.
        Assert.True(report.Passes[0].Counters["streams_added"] >= 1);

        // dnlib re-parses the protected image and decodes every method body (the CLR/dnlib tolerate
        // the construction and keep the real streams).
        StructuralValidator.Result v = StructuralValidator.Validate(prot);
        Assert.True(v.Ok, "structural issues: " + string.Join(" | ", v.Issues));

        ReaModel.Result r = ReaModel.Analyze(prot);
        // The construction is surfaced as a MEASURED metadata-layer denial of rea's inventory — a
        // fact, distinct from the modelled budget/caps.
        Assert.False(r.JtdPresent, "P6 no longer adds the no-op #JTD marker");
        Assert.True(r.ReaMetadataDenied, $"{variant} should be flagged as a measured rea denial");
        Assert.Contains(reasonFragment, r.DenialReason);
        // The denial is measured separately from the modelled hard-stop surface (honesty contract).
        Assert.False(r.AnyHardStop, "metadata denial is measured, not a modelled hard stop");

        // The .NET CLR loads the construction and runs the program identically — load-safety +
        // runtime equivalence of the P6 lever on this host.
        Assert.Equal(baseline, AssemblyRunner.RunToString(prot));
    }

    [Fact]
    public void P7_SelfSeal_EmbedsVerifiableDigest_DetectsTamper_AndExecutesEquivalently()
    {
        string baseline = AssemblyRunner.RunToString(Sample());
        (ProtectionReport report, byte[] prot) = Apply(new SelfSealPass());

        Assert.Equal(1, report.Passes[0].Counters["seal_embedded"]);
        Assert.True(SelfSealPass.VerifySeal(prot), "embedded seal must verify against the sealed bytes");

        // Any edit outside the slot breaks the seal (tamper-evidence).
        byte[] tampered = (byte[])prot.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(SelfSealPass.VerifySeal(tampered));

        // VerifyIntegrity is never called by real code, so behaviour is unchanged.
        Assert.Equal(baseline, AssemblyRunner.RunToString(prot));
    }

    [Fact]
    public void P8_RuntimeDecoyTelemetry_InjectsDecoys_AndExecutesEquivalently()
    {
        string baseline = AssemblyRunner.RunToString(Sample());
        (ProtectionReport report, byte[] prot) = Apply(new RuntimeDecoyTelemetryPass());

        Assert.Equal(baseline, AssemblyRunner.RunToString(prot));
        StructuralValidator.Result v = StructuralValidator.Validate(prot);
        Assert.True(v.Ok, "structural issues: " + string.Join(" | ", v.Issues));
        Assert.Equal(4, report.Passes[0].Counters["decoy_methods"]);

        Assert.True(RuntimeEquivalenceTests.ContainsUtf8(prot, "RuntimeGuard"), "expected RuntimeGuard decoy type");
        Assert.True(RuntimeEquivalenceTests.ContainsUtf16(prot, "telemetry.internal.example"), "expected beacon decoy string");
    }

    [Fact]
    public void P9_RepresentationBomb_PlantsQuadraticEdges_ModelExhausts_AndExecutesEquivalently()
    {
        string baseline = AssemblyRunner.RunToString(Sample());
        (ProtectionReport report, byte[] prot) = Apply(new RepresentationBombPass());

        // N dead methods + N dead fields → 2·N² cross-reference edges, spread over decoy types.
        PassReport pr = report.Passes[0];
        long n = pr.Counters["bomb_methods"];
        Assert.True(n >= 2, "bomb should plant methods");
        Assert.Equal(n, pr.Counters["bomb_fields"]);
        Assert.Equal(2L * n * n, pr.Counters["cross_ref_edges"]);
        Assert.True(pr.Counters["decoy_types"] >= 1);

        // The writer produced a well-formed, decodable assembly (dnlib re-parses it).
        StructuralValidator.Result v = StructuralValidator.Validate(prot);
        Assert.True(v.Ok, "structural issues: " + string.Join(" | ", v.Issues));

        // The quadratic edge set pushes the MODELLED representation charge past the 64 MiB budget —
        // the model's analogue of the MEASURED rea 'unavailable'/resource-limit exhaustion.
        ReaModel.Result r = ReaModel.Analyze(prot);
        Assert.True(r.CrossesBudget, $"modelled charge {r.BudgetFraction:P0} should cross the 64 MiB budget");

        // Byte-identical method bodies are shared by dnlib (one RVA), so on-disk growth stays small
        // (~O(N)); a non-shared write would balloon to multiple MB and fail this bound.
        Assert.True(report.GrowthBytes < 1_000_000, $"on-disk growth {report.GrowthBytes} B too large (bodies not shared?)");

        // Stealth: the decoy members use believable "sharded subsystem" names, not a random-id bank —
        // so the type names rea 6.9.0 leaks before the budget bites read as a plausible subsystem.
        Assert.True(
            RuntimeEquivalenceTests.ContainsUtf8(prot, "Coordinator")
            || RuntimeEquivalenceTests.ContainsUtf8(prot, "Partition")
            || RuntimeEquivalenceTests.ContainsUtf8(prot, "Segment"),
            "P9 decoys should use believable subsystem vocabulary");

        // The injected methods are unreachable, so the program runs identically.
        Assert.Equal(baseline, AssemblyRunner.RunToString(prot));
    }

    [Fact]
    public void GatedPasses_AreOffByDefault()
    {
        Assert.False(new RawMetadataPass().DefaultFor(Intensity.Maximum));
        Assert.False(new SelfSealPass().DefaultFor(Intensity.Maximum));
        Assert.False(new RuntimeDecoyTelemetryPass().DefaultFor(Intensity.Maximum));
        Assert.False(new RepresentationBombPass().DefaultFor(Intensity.Maximum));
    }
}
