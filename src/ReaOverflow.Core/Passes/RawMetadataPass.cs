using dnlib.DotNet.Writer;
using dnlib.IO;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Passes;

/// <summary>
/// P6 — Raw-metadata parser-break (GATED, never on by default). Emits an ECMA-335 metadata
/// construction the .NET CLR tolerates but a strict reader rejects: <b>two metadata streams with
/// the same name</b> (a duplicate stream).
///
/// ✅ MEASURED analysis-denial vs real rea (rea@6.7.0, this repo's fuzz campaign 2026-11-16). A
/// duplicate stream makes rea throw <c>"Duplicate metadata stream"</c> at layout parse, so
/// <c>inspect-managed-members</c>, <c>inspect-managed-artifact</c>, and
/// <c>inspect-managed-native-boundaries</c> all report the metadata as <c>malformed</c> with
/// <b>ZERO types / methods / fields / signatures / string literals</b> — rea's entire managed
/// static inventory is denied. The .NET 8 CLR and dnlib take the first stream of a name and ignore
/// the duplicate, so the assembly still loads and runs <b>identically</b> (proven by the
/// runtime-equivalence gate and the RawMetadata_* tests).
///
/// ⚠️ HONESTY: this is a metadata-layer <i>denial</i>, not a crash. rea exits 0 and clearly labels
/// the file <c>malformed</c>; it does not segfault or exit non-zero. The win is that rea yields no
/// managed members where the app runs fine. Equivalent measured constructions (same effect): more
/// than 64 metadata streams, or a stream name with a non-printable byte. (The older <c>#JTD</c>
/// marker was MEASURED to be a no-op — rea parses straight through it — and is not used here.)
///
/// SAFETY (why gated): stream-layer tricks are non-standard and can push past what a given CLR or
/// strict loader will accept. P6 is OFF by default and must be runtime-tested per target. Whether
/// THIS host loads a P6 build is reported by the verify runtime-equivalence gate and the
/// RawMetadata_* tests, not assumed. The measured rea denial is re-checkable with
/// <c>scripts/rea-p6-denial-gate.ps1</c> (or <c>.sh</c>).
/// </summary>
public sealed class RawMetadataPass : IProtectionPass
{
    public string Id => "P6";
    public string Name => "Raw-metadata parser-break (duplicate stream — measured rea denial)";
    public SafetyClass Safety => SafetyClass.Gated;
    public EvidenceStatus Status => EvidenceStatus.DesignedFor;
    public bool DefaultFor(Intensity intensity) => false; // opt-in only (--passes P6)

    public void Run(ProtectionContext ctx, PassReport report)
    {
        SeededPrng rng = ctx.Prng.Fork("p6-rawmeta");
        RawMetadataVariant variant = ctx.Options.RawMetadataVariant;

        byte[] NextBlob() { byte[] b = new byte[rng.Next(8, 24)]; rng.NextBytes(b); return b; }

        switch (variant)
        {
            case RawMetadataVariant.ManyStreams:
            {
                // >64 metadata streams. The CLR has NO stream-count cap (loads 200+ fine); rea caps
                // at 64 and throws "stream count outside the admitted range". ~62 decoys + the ~5
                // real streams clears 64.
                const int decoys = 62;
                for (int i = 0; i < decoys; i++)
                {
                    byte[] c = NextBlob();
                    string name = "#" + rng.NextIdentifier(rng.Next(3, 6)) + i.ToString("D2");
                    ctx.WriterCustomizations.Add(opts =>
                        opts.MetadataOptions.CustomHeaps.Add(new DataReaderHeap(name, ByteArrayDataReaderFactory.CreateReader(c))));
                }
                report.Count("streams_added", decoys);
                report.Count("exceeds_stream_cap", 1);
                report.EstimatedBytesAdded = decoys * 24 + 64;
                report.Notes.Add($"added {decoys} decoy metadata streams (total > rea's admitted 64) — MEASURED "
                    + "(rea@6.7.0 and 6.9.0): metadata malformed, 0 members across all managed inspectors. The CLR has no "
                    + "stream-count cap, so the app loads and runs identically.");
                break;
            }
            case RawMetadataVariant.NonPrintableStreamName:
            {
                // A stream name with a byte < 0x20 (a control char). rea requires printable ASCII
                // (0x20..0x7e) and throws "stream name is not printable ASCII". dnlib writes the raw
                // control byte; the CLR ignores the unknown stream. (Note: dnlib sanitizes bytes
                // ABOVE 0x7e to '?', so we use a low control char, which it preserves.)
                byte[] c = NextBlob();
                string name = "#\u0001" + rng.NextIdentifier(rng.Next(2, 4));
                ctx.WriterCustomizations.Add(opts =>
                    opts.MetadataOptions.CustomHeaps.Add(new DataReaderHeap(name, ByteArrayDataReaderFactory.CreateReader(c))));
                report.Count("streams_added", 1);
                report.Count("nonprintable_stream_name", 1);
                report.EstimatedBytesAdded = c.Length + 32;
                report.Notes.Add("added a metadata stream whose name contains a non-printable (control) byte — MEASURED "
                    + "(rea@6.7.0 and 6.9.0): metadata malformed, 0 members across all managed inspectors. The CLR ignores "
                    + "the unknown stream, so the app loads and runs identically.");
                break;
            }
            default: // DuplicateStream
            {
                // Two metadata streams that share one name. The CLR/dnlib keep the first and ignore
                // the second; a strict ECMA-335 reader throws "Duplicate metadata stream".
                string dupName = "#" + rng.NextIdentifier(rng.Next(3, 6));
                byte[] first = NextBlob();
                byte[] second = NextBlob();
                ctx.WriterCustomizations.Add(opts =>
                {
                    opts.MetadataOptions.CustomHeaps.Add(new DataReaderHeap(dupName, ByteArrayDataReaderFactory.CreateReader(first)));
                    opts.MetadataOptions.CustomHeaps.Add(new DataReaderHeap(dupName, ByteArrayDataReaderFactory.CreateReader(second)));
                });
                report.Count("streams_added", 2);
                report.Count("duplicate_stream_name", 1);
                report.EstimatedBytesAdded = first.Length + second.Length + 64;
                report.Notes.Add($"added a DUPLICATE metadata stream '{dupName}' (two streams, one name) — MEASURED (rea@6.7.0 "
                    + "and 6.9.0): metadata reported malformed with 0 members across inspect-managed-members / -artifact / -native-boundaries.");
                break;
            }
        }

        report.Notes.Add($"P6 variant: {variant} (select with --p6-variant dup|manystreams|badname).");
        report.Notes.Add(".NET 8 CLR + dnlib still load and run the assembly identically (proven by runtime-equivalence). "
            + "rea exits 0 and flags the file malformed — this is a denial, not a crash.");
        report.Notes.Add("GATED: these constructions are non-standard; other runtimes/strict loaders may reject — verify "
            + "runtime-equivalence per target. Re-check the rea denial with scripts/rea-p6-denial-gate.ps1 / .sh.");
    }
}
