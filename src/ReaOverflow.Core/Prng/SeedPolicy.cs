using System;
using System.Globalization;
using System.Security.Cryptography;

namespace ReaOverflow.Core.Prng;

/// <summary>
/// Resolves the project seed for a CLI run. Open-source hardening: a missing <c>--seed</c> yields a
/// cryptographically-random per-build seed (so two builds of the same input share NO static strip
/// signature); an explicit <c>--seed</c> is parsed for reproducible builds/tests/gates. The seed is
/// the secret (Kerckhoffs): never embed it in the artifact; log it so a build can be reproduced.
/// </summary>
public static class SeedPolicy
{
    public static (ulong Seed, bool WasRandom) Resolve(string? seedArg)
    {
        if (seedArg is not null)
            return (Parse(seedArg), false);

        Span<byte> b = stackalloc byte[8];
        RandomNumberGenerator.Fill(b);
        return (BitConverter.ToUInt64(b), true);
    }

    public static ulong Parse(string seedArg)
    {
        string s = seedArg.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.Parse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        return ulong.Parse(s, NumberStyles.Integer, CultureInfo.InvariantCulture);
    }
}
