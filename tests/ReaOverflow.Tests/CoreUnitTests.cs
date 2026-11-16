using System.Collections.Generic;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using Xunit;

namespace ReaOverflow.Tests;

public class SeededPrngTests
{
    [Fact]
    public void SameSeed_ProducesSameSequence()
    {
        var a = new SeededPrng(12345);
        var b = new SeededPrng(12345);
        for (int i = 0; i < 1000; i++)
            Assert.Equal(a.NextUInt64(), b.NextUInt64());
    }

    [Fact]
    public void DifferentSeed_Diverges()
    {
        var a = new SeededPrng(1);
        var b = new SeededPrng(2);
        bool anyDifferent = false;
        for (int i = 0; i < 100; i++)
            if (a.NextUInt64() != b.NextUInt64()) { anyDifferent = true; break; }
        Assert.True(anyDifferent);
    }

    [Fact]
    public void Next_RespectsBounds()
    {
        var p = new SeededPrng(99);
        for (int i = 0; i < 10000; i++)
        {
            int v = p.Next(5, 10);
            Assert.InRange(v, 5, 9);
        }
    }

    [Fact]
    public void NextIdentifier_IsLegalAndStartsWithLetterOrUnderscore()
    {
        var p = new SeededPrng(7);
        for (int i = 0; i < 500; i++)
        {
            string id = p.NextIdentifier(10);
            Assert.Equal(10, id.Length);
            char c0 = id[0];
            Assert.True(char.IsLetter(c0) || c0 == '_');
            foreach (char c in id) Assert.True(char.IsLetterOrDigit(c) || c == '_');
        }
    }

    [Fact]
    public void Fork_IsDeterministic_ButDistinctFromParent()
    {
        var parent1 = new SeededPrng(42);
        var parent2 = new SeededPrng(42);
        var f1 = parent1.Fork("x");
        var f2 = parent2.Fork("x");
        Assert.Equal(f1.NextUInt64(), f2.NextUInt64());

        var other = new SeededPrng(42).Fork("y");
        Assert.NotEqual(new SeededPrng(42).Fork("x").NextUInt64(), other.NextUInt64());
    }
}

public class SizeBudgetTests
{
    [Fact]
    public void UsesAbsoluteFloor_WhenFractionIsSmaller()
    {
        var b = new SizeBudget(originalBytes: 1000, maxGrowthFraction: 0.25, minAbsoluteGrowth: 512 * 1024);
        Assert.Equal(512 * 1024, b.MaxGrowthBytes); // 250 bytes < 512 KiB floor
    }

    [Fact]
    public void UsesFraction_WhenLarger()
    {
        var b = new SizeBudget(originalBytes: 100_000_000, maxGrowthFraction: 0.25, minAbsoluteGrowth: 512 * 1024);
        Assert.Equal(25_000_000, b.MaxGrowthBytes);
    }

    [Fact]
    public void TryReserve_VetoesOverflow_AndKeepsRunningTotal()
    {
        var b = new SizeBudget(1000, 0.0, minAbsoluteGrowth: 100);
        Assert.True(b.TryReserve(60));
        Assert.True(b.TryReserve(40));
        Assert.False(b.TryReserve(1));      // would exceed 100
        Assert.Equal(100, b.ReservedBytes);
        Assert.Equal(0, b.RemainingBytes);
    }
}
