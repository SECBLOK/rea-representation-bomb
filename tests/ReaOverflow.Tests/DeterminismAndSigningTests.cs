using System.IO;
using System.Linq;
using dnlib.DotNet;
using ReaOverflow.Core.Passes;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Report;
using Xunit;

namespace ReaOverflow.Tests;

public class DeterminismAndSigningTests
{
    private static IProtectionPass[] Stack() => new IProtectionPass[]
    {
        new OpaquePredicatePass(), new MbaSubstitutionPass(),
        new DecoyArchetypePass(), new MetadataInflationPass(),
    };

    [Fact]
    public void SameSeed_ProducesByteIdenticalOutput()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        var opts = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0x1234 };

        (ProtectionReport _, byte[] a) = Protector.ProtectToBytes(original, opts, Stack());
        (ProtectionReport _, byte[] b) = Protector.ProtectToBytes(original, opts, Stack());

        Assert.Equal(a.Length, b.Length);
        Assert.True(a.AsSpan().SequenceEqual(b), "same seed must produce byte-identical output (reproducible builds)");
    }

    [Fact]
    public void DifferentSeed_ProducesDifferentOutput()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        (ProtectionReport _, byte[] a) = Protector.ProtectToBytes(original,
            new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0x1111 }, Stack());
        (ProtectionReport _, byte[] b) = Protector.ProtectToBytes(original,
            new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0x2222 }, Stack());

        Assert.False(a.Length == b.Length && a.AsSpan().SequenceEqual(b),
            "different seeds must produce different output (seeded decoys/names/keys)");
    }

    [Fact]
    public void NotStrongNamed_ProducesNoSigningWarning()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        (ProtectionReport report, _) = Protector.ProtectToBytes(original,
            new ProtectionOptions { Intensity = Intensity.Balanced }, Stack());
        Assert.DoesNotContain(report.Warnings, w => w.Contains("strong-name"));
    }

    [Fact]
    public void StrongNamedInput_WarnsThatSignatureIsInvalidated()
    {
        // Give the sample a (fake) public key so it presents as strong-named, then protect it.
        byte[] signed;
        using (var m = ModuleDefMD.Load(File.ReadAllBytes(SampleLocator.HelloTargetDll())))
        {
            m.Assembly.PublicKey = new PublicKey(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            using var ms = new MemoryStream();
            m.Write(ms);
            signed = ms.ToArray();
        }

        (ProtectionReport report, _) = Protector.ProtectToBytes(signed,
            new ProtectionOptions { Intensity = Intensity.Balanced }, Stack());
        Assert.Contains(report.Warnings, w => w.Contains("strong-name"));
    }
}
