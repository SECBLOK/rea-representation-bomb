using ReaOverflow.Core.Prng;
using Xunit;

namespace ReaOverflow.Tests;

public class SeedPolicyTests
{
    [Fact]
    public void ExplicitHexSeed_IsParsed_Deterministically()
    {
        var (seed, wasRandom) = SeedPolicy.Resolve("0x1234ABCD");
        Assert.Equal(0x1234ABCDUL, seed);
        Assert.False(wasRandom);
    }

    [Fact]
    public void ExplicitDecimalSeed_IsParsed()
    {
        var (seed, wasRandom) = SeedPolicy.Resolve("42");
        Assert.Equal(42UL, seed);
        Assert.False(wasRandom);
    }

    [Fact]
    public void NoSeed_IsRandom_AndDiffersBetweenCalls()
    {
        var (a, aRandom) = SeedPolicy.Resolve(null);
        var (b, bRandom) = SeedPolicy.Resolve(null);
        Assert.True(aRandom);
        Assert.True(bRandom);
        Assert.NotEqual(a, b); // 1 - 2^-64 chance; a flake here is effectively impossible
    }
}
