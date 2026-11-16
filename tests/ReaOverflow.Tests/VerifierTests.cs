using System;
using System.IO;
using System.Linq;
using ReaOverflow.Core.Passes;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Report;
using Xunit;

namespace ReaOverflow.Tests;

public class VerifierTests
{
    [Fact]
    public void Verify_P5Protected_PassesAllCriticalGates()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xA11CE };
        (ProtectionReport _, byte[] prot) =
            Protector.ProtectToBytes(original, options, new IProtectionPass[] { new MetadataInflationPass() });

        Verifier.Report rep = Verifier.Verify(original, prot);

        Assert.True(rep.Ok, "critical gate failed: " +
            string.Join(" | ", rep.Gates.Where(g => g.Outcome == Verifier.Outcome.Fail).Select(g => g.Name)));
        Assert.Equal(Verifier.Outcome.Pass, rep.Gates.Single(g => g.Name == "structural").Outcome);
        Assert.Equal(Verifier.Outcome.Pass, rep.Gates.Single(g => g.Name == "runtime-equivalence").Outcome);
        Assert.Equal(Verifier.Outcome.Pass, rep.Gates.Single(g => g.Name == "rea-budget (modelled)").Outcome);
    }

    [Fact]
    public void Verify_IdentityCopy_FailsBudgetGate()
    {
        // An unprotected copy is runtime-equivalent but does NOT exhaust REA's budget → not clear.
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        Verifier.Report rep = Verifier.Verify(original, (byte[])original.Clone());

        Assert.False(rep.Ok);
        Assert.Equal(Verifier.Outcome.Fail, rep.Gates.Single(g => g.Name == "rea-budget (modelled)").Outcome);
        Assert.Equal(Verifier.Outcome.Pass, rep.Gates.Single(g => g.Name == "runtime-equivalence").Outcome);
    }
}
