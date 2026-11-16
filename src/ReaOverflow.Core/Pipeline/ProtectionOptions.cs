using System.Collections.Generic;

namespace ReaOverflow.Core.Pipeline;

public enum Intensity
{
    Stealth = 0,
    Balanced = 1,
    Maximum = 2,
}

/// <summary>
/// Which load-safe metadata construction P6 (<see cref="Passes.RawMetadataPass"/>) emits. All three
/// are MEASURED to deny rea's managed inventory (metadata malformed, 0 members) on rea@6.7.0 and
/// 6.9.0 while the .NET 8 CLR loads and runs the assembly identically.
/// </summary>
public enum RawMetadataVariant
{
    /// <summary>Two metadata streams with the same name — rea: "Duplicate metadata stream". Default.</summary>
    DuplicateStream = 0,
    /// <summary>More than 64 metadata streams — rea: "stream count outside the admitted range" (the CLR has no cap).</summary>
    ManyStreams = 1,
    /// <summary>A stream name containing a non-printable byte — rea: "stream name is not printable ASCII".</summary>
    NonPrintableStreamName = 2,
}

/// <summary>Runtime-safety classification per the tech spec (§4).</summary>
public enum SafetyClass
{
    /// <summary>Proven loadable + runtime-equivalent on validated targets.</summary>
    Safe,
    /// <summary>Must pass per-target runtime tests before enabling; off by default.</summary>
    Gated,
    /// <summary>No security guarantee; misleads a live analyst only.</summary>
    Decorative,
}

public sealed class ProtectionOptions
{
    /// <summary>Default is a fixed sentinel; the CLI derives a per-project seed when unset.</summary>
    public ulong Seed { get; set; } = 0x5EA0_0F10_0000_0001UL;

    public Intensity Intensity { get; set; } = Intensity.Balanced;

    /// <summary>Pass ids to run. Null/empty = each pass decides via its default policy.</summary>
    public HashSet<string>? EnabledPasses { get; set; }

    /// <summary>Max added bytes as a fraction of the original size (default 25%).</summary>
    public double MaxGrowthFraction { get; set; } = 0.25;

    /// <summary>Floor for allowed growth regardless of original size (default 512 KiB).</summary>
    public long MinAbsoluteGrowth { get; set; } = 512 * 1024;

    /// <summary>
    /// Path to a strong-name key (.snk) to sign the protected assembly with AFTER all transforms.
    /// Null = no signing. Protection always invalidates an input's existing signature, so this
    /// re-establishes one. Incompatible with post-write passes (P7), which edit bytes after signing.
    /// </summary>
    public string? SignKeyPath { get; set; }

    /// <summary>Which load-safe metadata construction P6 emits (default <see cref="RawMetadataVariant.DuplicateStream"/>).</summary>
    public RawMetadataVariant RawMetadataVariant { get; set; } = RawMetadataVariant.DuplicateStream;

    public bool IsEnabled(string passId, bool defaultForIntensity)
        => EnabledPasses is { Count: > 0 } ? EnabledPasses.Contains(passId) : defaultForIntensity;
}
