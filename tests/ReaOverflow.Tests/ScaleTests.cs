using System;
using System.IO;
using ReaOverflow.Core.Analysis;
using ReaOverflow.Core.Passes;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Report;
using Xunit;

namespace ReaOverflow.Tests;

/// <summary>Proves the transforms hold up on a larger, real assembly — not just the toy sample.</summary>
public class ScaleTests
{
    private static string CoreDll()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ReaOverflow.slnx")))
            dir = dir.Parent;
        if (dir is null) throw new FileNotFoundException("repo root (ReaOverflow.slnx) not found");
        string path = Path.Combine(dir.FullName, "src", "ReaOverflow.Core", "bin", "Release", "net8.0", "ReaOverflow.Core.dll");
        if (!File.Exists(path)) throw new FileNotFoundException($"not built: {path}");
        return path;
    }

    [Fact]
    public void FullStack_ProtectsALargerRealAssembly_StaysStructurallyValid_AndDegrades()
    {
        byte[] original = File.ReadAllBytes(CoreDll());
        DegradationMetrics.Metrics before = DegradationMetrics.Measure(original);

        var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xC0FFEE };
        var passes = new IProtectionPass[]
        {
            new OpaquePredicatePass(), new MbaSubstitutionPass(),
            new DecoyArchetypePass(), new MetadataInflationPass(),
        };
        (ProtectionReport report, byte[] prot) = Protector.ProtectToBytes(original, options, passes);

        // Writer produced a well-formed, fully-decodable image from ~64 KB of real IL.
        StructuralValidator.Result v = StructuralValidator.Validate(prot);
        Assert.True(v.Ok, "structural issues: " + string.Join(" | ", v.Issues));
        Assert.True(v.MethodsDecoded > 50, $"only {v.MethodsDecoded} methods decoded");

        // Budget crossed and the reader's signal degraded (more types + instructions).
        Assert.True(ReaModel.Analyze(prot).CrossesBudget);
        DegradationMetrics.Metrics after = DegradationMetrics.Measure(prot);
        Assert.True(after.TypeCount > before.TypeCount);
        Assert.True(after.Instructions > before.Instructions);

        // Disk growth is still governed by the size budget (not proportional to the 64 MiB charge).
        Assert.True(report.GrowthBytes < 1_000_000, $"disk grew too much: {report.GrowthBytes:N0}");
    }
}
