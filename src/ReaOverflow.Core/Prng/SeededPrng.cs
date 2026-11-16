using System;
using System.Security.Cryptography;
using System.Text;

namespace ReaOverflow.Core.Prng;

/// <summary>
/// Deterministic, platform-independent PRNG (splitmix64 seed → xoshiro256**).
/// Every generator (decoy names, opaque-predicate constants, keystreams) is driven by this
/// so a given project seed produces identical, collision-free output across builds and OSes.
/// Pure integer math — no <see cref="Random"/>, no clock.
/// </summary>
public sealed class SeededPrng
{
    private ulong _s0, _s1, _s2, _s3;

    public ulong Seed { get; }

    public SeededPrng(ulong seed)
    {
        Seed = seed;
        ulong z = seed;
        _s0 = SplitMix64(ref z);
        _s1 = SplitMix64(ref z);
        _s2 = SplitMix64(ref z);
        _s3 = SplitMix64(ref z);
        // Avoid the all-zero state.
        if ((_s0 | _s1 | _s2 | _s3) == 0) _s0 = 0x9E3779B97F4A7C15UL;
    }

    /// <summary>Derive a seed from an arbitrary string (e.g. a project name) via SHA-256.</summary>
    public static ulong SeedFromString(string text)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(text ?? string.Empty));
        return BitConverter.ToUInt64(hash, 0);
    }

    /// <summary>Fork a child generator deterministically bound to this one and a label.</summary>
    public SeededPrng Fork(string label) => new(NextUInt64() ^ SeedFromString(label));

    private static ulong SplitMix64(ref ulong x)
    {
        x = unchecked(x + 0x9E3779B97F4A7C15UL);
        ulong z = x;
        z = unchecked((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL);
        z = unchecked((z ^ (z >> 27)) * 0x94D049BB133111EBUL);
        return z ^ (z >> 31);
    }

    private static ulong Rotl(ulong x, int k) => (x << k) | (x >> (64 - k));

    public ulong NextUInt64()
    {
        ulong result = unchecked(Rotl(_s1 * 5, 7) * 9);
        ulong t = _s1 << 17;
        _s2 ^= _s0;
        _s3 ^= _s1;
        _s1 ^= _s2;
        _s0 ^= _s3;
        _s2 ^= t;
        _s3 = Rotl(_s3, 45);
        return result;
    }

    public uint NextUInt32() => (uint)(NextUInt64() >> 32);

    /// <summary>Uniform-ish integer in [minInclusive, maxExclusive).</summary>
    public int Next(int minInclusive, int maxExclusive)
    {
        if (maxExclusive <= minInclusive) return minInclusive;
        ulong range = (ulong)(maxExclusive - minInclusive);
        return minInclusive + (int)(NextUInt64() % range);
    }

    public bool NextBool() => (NextUInt64() & 1) == 1;

    public void NextBytes(Span<byte> buffer)
    {
        int i = 0;
        while (i < buffer.Length)
        {
            ulong v = NextUInt64();
            for (int b = 0; b < 8 && i < buffer.Length; b++, i++)
                buffer[i] = (byte)(v >> (b * 8));
        }
    }

    private const string IdentChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string IdentStart = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";

    /// <summary>A legal, deterministic C# identifier of the given length.</summary>
    public string NextIdentifier(int length = 12)
    {
        if (length < 1) length = 1;
        var sb = new StringBuilder(length);
        sb.Append(IdentStart[Next(0, IdentStart.Length)]);
        for (int i = 1; i < length; i++)
            sb.Append(IdentChars[Next(0, IdentChars.Length)]);
        return sb.ToString();
    }
}
