using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Passes;

/// <summary>
/// P7 — Self-seal / entangle (GATED, off by default). Embeds a SHA-256 digest of the final image
/// into the image itself: a locatable sentinel marks a 64-char slot, and after the module is
/// written the slot is zeroed, the whole file is hashed, and the hex digest is written back into
/// the slot. The embedded digest therefore equals <c>SHA-256(file with the slot zeroed)</c> — any
/// post-build byte edit changes the hash and no longer matches, so the seal is live tamper-evidence
/// that an external launcher (or the user's own loader) can check.
///
/// A decorative <c>SealGuard.VerifyIntegrity()</c> is injected so the seal looks enforced in the
/// decompile. HONESTY: enforcement is opt-in — a managed assembly cannot robustly hash its own file
/// at runtime (single-file/trimmed/in-memory builds have no file path), so the running check is
/// decorative; the real guarantee is the correctly-sealed digest, verifiable out-of-process. Also:
/// sealing invalidates Authenticode/strong-name signatures (sign AFTER protecting, or verify the
/// seal instead). Gated and off by default.
/// </summary>
public sealed class SelfSealPass : IProtectionPass
{
    public string Id => "P7";
    public string Name => "Self-seal / entangle";
    public SafetyClass Safety => SafetyClass.Gated;
    public EvidenceStatus Status => EvidenceStatus.DesignedFor;
    public bool DefaultFor(Intensity intensity) => false; // opt-in only (--passes P7)

    internal const string Sentinel = "ROSEALv1";
    internal const int DigestHexLen = 64; // SHA-256 as lowercase hex

    private static readonly string[] Roots = { "Helios", "Aurora", "Meridian", "Vertex", "Nimbus", "Cobalt" };

    public void Run(ProtectionContext ctx, PassReport report)
    {
        SeededPrng rng = ctx.Prng.Fork("p7-seal");
        if (!ctx.Budget.TryReserve(400))
        {
            report.Notes.Add("size budget reached; self-seal skipped");
            return;
        }

        string placeholder = Sentinel + new string('0', DigestHexLen);
        InjectSealGuard(ctx, rng, placeholder);

        ctx.PostWriteTransforms.Add(bytes =>
        {
            (byte[] sealed_, bool ok) = PatchSeal(bytes);
            report.Notes.Add(ok
                ? "seal embedded: SHA-256(file with slot zeroed) written into the sentinel slot"
                : "seal sentinel not found uniquely in #US; seal NOT embedded (report-only)");
            if (ok) report.Count("seal_embedded", 1);
            return sealed_;
        });

        report.Count("seal_guard_injected", 1);
        report.Notes.Add("GATED: runtime enforcement is opt-in (managed self-hash is deployment-dependent); sign AFTER protecting");
    }

    private static void InjectSealGuard(ProtectionContext ctx, SeededPrng rng, string placeholder)
    {
        string root = Roots[rng.Next(0, Roots.Length)];
        var t = new TypeDefUser($"{root}.Security", "SealGuard", ctx.Cor.Object.TypeDefOrRef)
        {
            Attributes = dnlib.DotNet.TypeAttributes.NotPublic | dnlib.DotNet.TypeAttributes.AutoLayout
                         | dnlib.DotNet.TypeAttributes.AnsiClass | dnlib.DotNet.TypeAttributes.Sealed
                         | dnlib.DotNet.TypeAttributes.BeforeFieldInit,
        };
        ctx.Module.Types.Add(t);

        var sig = MethodSig.CreateStatic(ctx.Cor.Boolean);
        var m = new MethodDefUser("VerifyIntegrity", sig, MethodImplAttributes.IL | MethodImplAttributes.Managed,
            dnlib.DotNet.MethodAttributes.Assembly | dnlib.DotNet.MethodAttributes.Static
                | dnlib.DotNet.MethodAttributes.HideBySig);
        var body = new CilBody { InitLocals = true, MaxStack = 2 };
        IList<Instruction> il = body.Instructions;
        il.Add(OpCodes.Ldstr.ToInstruction(placeholder)); // the seal slot lands in #US here
        il.Add(OpCodes.Pop.ToInstruction());
        il.Add(OpCodes.Ldc_I4_1.ToInstruction());         // decorative: "intact"
        il.Add(OpCodes.Ret.ToInstruction());
        m.Body = body;
        body.OptimizeMacros();
        t.Methods.Add(m);
    }

    /// <summary>
    /// Finds the sentinel in the written bytes, zeroes the 64-char slot after it, hashes the whole
    /// file, and writes the hex digest into the slot. Returns (bytes, embedded?).
    /// </summary>
    internal static (byte[] Bytes, bool Embedded) PatchSeal(byte[] file)
    {
        byte[] pattern = Encoding.Unicode.GetBytes(Sentinel + new string('0', DigestHexLen));
        int idx = IndexOf(file, pattern, out bool unique);
        if (idx < 0 || !unique) return (file, false);

        int slotStart = idx + Encoding.Unicode.GetByteCount(Sentinel);
        int slotLen = DigestHexLen * 2; // UTF-16

        var outBytes = (byte[])file.Clone();
        Array.Clear(outBytes, slotStart, slotLen);               // canonical: slot zeroed for hashing
        byte[] digest = SHA256.HashData(outBytes);
        byte[] hex = Encoding.Unicode.GetBytes(ToHex(digest));   // 64 chars → 128 bytes, fills the slot
        Buffer.BlockCopy(hex, 0, outBytes, slotStart, slotLen);
        return (outBytes, true);
    }

    /// <summary>Re-derives the seal from a sealed file and reports whether it matches (for tests/tools).</summary>
    internal static bool VerifySeal(byte[] sealedFile)
    {
        byte[] sentinel = Encoding.Unicode.GetBytes(Sentinel);
        int idx = IndexOf(sealedFile, sentinel, out _);
        if (idx < 0) return false;
        int slotStart = idx + sentinel.Length;
        int slotLen = DigestHexLen * 2;
        if (slotStart + slotLen > sealedFile.Length) return false;

        string stored = Encoding.Unicode.GetString(sealedFile, slotStart, slotLen);
        var probe = (byte[])sealedFile.Clone();
        Array.Clear(probe, slotStart, slotLen);
        return string.Equals(stored, ToHex(SHA256.HashData(probe)), StringComparison.Ordinal);
    }

    private static int IndexOf(byte[] haystack, byte[] needle, out bool unique)
    {
        int first = -1, count = 0;
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            int j = 0;
            while (j < needle.Length && haystack[i + j] == needle[j]) j++;
            if (j == needle.Length)
            {
                if (first < 0) first = i;
                count++;
            }
        }
        unique = count == 1;
        return first;
    }

    private static string ToHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
