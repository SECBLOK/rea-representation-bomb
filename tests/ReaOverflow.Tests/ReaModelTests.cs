using System.IO;
using System.Linq;
using ReaOverflow.Core.Analysis;
using Xunit;

namespace ReaOverflow.Tests;

public class ReaModelTests
{
    [Fact]
    public void Baseline_Sample_IsWellUnderBudget_AndChargesEveryCategory()
    {
        byte[] bytes = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        ReaModel.Result r = ReaModel.Analyze(bytes);

        // A small honest assembly must be cheap for REA — nowhere near the 64 MiB budget.
        Assert.False(r.CrossesBudget);
        Assert.False(r.AnyHardStop);
        Assert.StartsWith("ok", r.PredictedStatus);

        // Every modelled charge category should be present and non-negative.
        Assert.Equal(5, r.Breakdown.Count);
        Assert.All(r.Breakdown, c => Assert.True(c.Bytes >= 0));
        Assert.True(r.Breakdown.Sum(c => c.Bytes) == r.TotalChargeBytes);
        Assert.True(r.TotalChargeBytes > 0);
    }

    [Fact]
    public void Constants_Match_Rea_Ceilings()
    {
        Assert.Equal(64L * 1024 * 1024, ReaModel.RepresentationBudgetBytes);
        Assert.Equal(128L * 1024 * 1024, ReaModel.SnapshotCapBytes);
        Assert.Equal(256, ReaModel.BytesPerRow);
        Assert.Equal(256, ReaModel.BytesPerInstruction);
        Assert.Equal(256, ReaModel.BlobChargePerByte);
        Assert.Equal(512, ReaModel.BytesPerType);
        Assert.Equal(64, ReaModel.MaxTypeNestingDepth);
        Assert.Equal(32, ReaModel.MaxArrayRank);
    }
}
