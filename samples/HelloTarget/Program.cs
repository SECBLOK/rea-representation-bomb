// HelloTarget — a small, fully deterministic sample app used to prove that
// ReaOverflow's transforms preserve runtime behaviour (no external input, no clock,
// no randomness → identical output every run).
using System;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;

namespace HelloTarget;

internal static class Program
{
    private static int Main()
    {
        var sb = new StringBuilder();
        sb.AppendLine("ReaOverflow sample target v1");
        sb.AppendLine("license-status=" + CheckLicense("ACME-ENTERPRISE-2026"));
        sb.AppendLine("feature-score=" + FeatureScore(7, 13).ToString(CultureInfo.InvariantCulture));
        sb.AppendLine("secret=" + RevealSecret());
        sb.AppendLine("checksum=" + Checksum("the quick brown fox").ToString("X8", CultureInfo.InvariantCulture));
        sb.AppendLine("async-sum=" + AsyncAccumulate().GetAwaiter().GetResult().ToString(CultureInfo.InvariantCulture));
        sb.AppendLine("heap-min=" + HeapMin().ToString(CultureInfo.InvariantCulture));
        sb.AppendLine("longloop=" + LongLoopSum().ToString(CultureInfo.InvariantCulture));
        Console.Write(sb.ToString());
        return 0;
    }

    // A loop whose body is long and constant-dense. P3 (MBA) inserts 6 instructions at each selected
    // ldc.i4 site; with many sites the body exceeds a short branch's ±127-byte reach, so the for-loop's
    // back-edge branch must be re-encoded to long form or it corrupts (the branch-overflow bug). The
    // result must stay identical across every seed. Deterministic.
    private static long LongLoopSum()
    {
        long acc = 0;
        for (int i = 0; i < 20; i++)
        {
            int a = (i * 3) + 7;
            int b = (a ^ 19) + 23;
            int c = (b * 5) - 11;
            int d = (c | 31) + 13;
            int e = (d & 127) + 17;
            int f = (e << 2) + 29;
            int g = (f + 41) ^ 9;
            acc += unchecked(a + b + c + d + e + f + g);
        }
        return acc;
    }

    // Builds a min-heap by sifting each element up; returns the root (minimum). The sift loop's
    // 'while (i > 0)' ENTRY guard is load-bearing: the first Offer calls SiftUp(0), and without the
    // guard that computes p = (0-1)>>1 = -1 and indexes h[-1]. A transform that rewrites constants
    // inside this loop (P3 MBA) must preserve the guard, or this throws IndexOutOfRange — the exact
    // failure seen in filehound's BoundedHeap. Deterministic result: min of the seed set == 1.
    private static int HeapMin()
    {
        ReadOnlySpan<int> seed = stackalloc int[] { 5, 3, 8, 1, 9, 2, 7 };
        Span<int> h = stackalloc int[seed.Length];
        int count = 0;
        foreach (int v in seed)
        {
            h[count] = v;
            SiftUp(h, count++); // first call passes i = 0
        }
        return h[0];
    }

    private static void SiftUp(Span<int> h, int i)
    {
        while (i > 0)
        {
            int p = (i - 1) >> 1;
            if (h[p] <= h[i]) break;
            (h[p], h[i]) = (h[i], h[p]);
            i = p;
        }
    }

    // A real async state machine: 'await' inside a loop forces the compiler-generated MoveNext to
    // suspend and resume on its <>1__state dispatch. P2 (opaque predicates) and P3 (MBA) must NOT
    // rewrite that generated body — doing so corrupts the state dispatch (task double-completion /
    // NRE), the exact failure seen on real async-heavy code. Deterministic result: sum of i*i for
    // i=1..10 == 385.
    private static async Task<int> AsyncAccumulate()
    {
        int sum = 0;
        for (int i = 1; i <= 10; i++)
        {
            await Task.Yield();
            sum = unchecked(sum + i * i);
        }
        return sum;
    }

    // A fake-but-deterministic "license check" (real-logic stand-in that must keep working).
    private static bool CheckLicense(string key)
    {
        int acc = 0;
        foreach (char c in key)
            acc = unchecked(acc * 31 + c);
        return (acc & 0x7) == ((key.Length * 3) & 0x7);
    }

    private static int FeatureScore(int a, int b)
    {
        // Arithmetic that MBA substitution (P3) will later rewrite; must stay equal.
        int x = a + b;
        int y = a * b;
        return unchecked((x << 2) ^ (y + 11));
    }

    private static string RevealSecret()
    {
        // A sensitive string that string-encryption (P1) must hide statically but reveal at runtime.
        return "api-token-9F3A-DO-NOT-SHIP-PLAINTEXT";
    }

    private static uint Checksum(string s)
    {
        uint h = 2166136261u; // FNV-1a
        foreach (char c in s)
        {
            h ^= c;
            h = unchecked(h * 16777619u);
        }
        return h;
    }
}
