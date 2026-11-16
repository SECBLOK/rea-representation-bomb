using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ReaOverflow.Core.Analysis;

/// <summary>
/// Measures the static "signal" an LLM/analyst can read off an assembly, so a before/after
/// comparison shows how much protection degraded it. All metrics come from an independent dnlib
/// re-parse (no execution), so this works even when AV blocks loading the image.
///
/// These are structural proxies, honestly labelled — e.g. "strings with whitespace" stands in for
/// human-readable literals (base64 ciphertext from P1 has none), and higher instruction/type counts
/// mean more decoy noise to wade through. It is not a decompiler; an independent ilspycmd pass is
/// the documented manual cross-check.
/// </summary>
public static class DegradationMetrics
{
    public sealed record Metrics(
        int DistinctStrings,
        int ReadableStrings,
        int TypeCount,
        int MethodBodies,
        long Instructions)
    {
        public double ReadableFraction => DistinctStrings > 0 ? (double)ReadableStrings / DistinctStrings : 0;
    }

    public static Metrics Measure(byte[] assemblyBytes)
    {
        var module = ModuleDefMD.Load(assemblyBytes);
        try
        {
            var strings = new HashSet<string>();
            int readable = 0, typeCount = 0, bodies = 0;
            long instrs = 0;

            foreach (TypeDef type in module.GetTypes())
            {
                typeCount++;
                foreach (MethodDef m in type.Methods)
                {
                    if (!m.HasBody || m.Body is null) continue;
                    bodies++;
                    foreach (Instruction instr in m.Body.Instructions)
                    {
                        instrs++;
                        if (instr.Operand is string s && strings.Add(s) && IsReadable(s))
                            readable++;
                    }
                }
            }
            return new Metrics(strings.Count, readable, typeCount, bodies, instrs);
        }
        finally
        {
            module.Dispose();
        }
    }

    /// <summary>
    /// Heuristic: a literal reads as human-meaningful if it has a real word (a 4+ letter run) and a
    /// human separator — space, '-', '_', '.', ':'. P1's standard base64 ciphertext uses only
    /// '+', '/', '=' and never those separators, so encrypting strings drives this count down, while
    /// sentences, paths, URLs and messages ("license-status", the beacon URL, "PBKDF2-HMAC-SHA256")
    /// still count. Single bare identifiers are undercounted, but consistently on both sides, so the
    /// before/after delta stays meaningful.
    /// </summary>
    private static bool IsReadable(string s)
    {
        if (s.Length < 4) return false;
        int longestRun = 0, run = 0, seps = 0;
        foreach (char c in s)
        {
            if (char.IsLetter(c)) { run++; if (run > longestRun) longestRun = run; }
            else { run = 0; if (c == ' ' || c == '-' || c == '_' || c == '.' || c == ':') seps++; }
        }
        return longestRun >= 4 && seps >= 1;
    }
}
