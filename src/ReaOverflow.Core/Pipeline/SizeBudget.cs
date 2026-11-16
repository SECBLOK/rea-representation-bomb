using System;

namespace ReaOverflow.Core.Pipeline;

/// <summary>
/// Enforces the "same effect, small file" constraint. Passes must ask before adding structure;
/// the pipeline refuses growth beyond the configured ceiling so protection never bloats the
/// artifact (the design aim is analysis cost via structure, not disk bytes; the modelled charge-
/// multipliers are optimistic — the measured effect is a token tax, not budget exhaustion).
/// </summary>
public sealed class SizeBudget
{
    private long _reserved;

    public long OriginalBytes { get; }

    /// <summary>Absolute ceiling of *added* bytes (estimated).</summary>
    public long MaxGrowthBytes { get; }

    public long ReservedBytes => _reserved;

    public SizeBudget(long originalBytes, double maxGrowthFraction, long minAbsoluteGrowth)
    {
        OriginalBytes = Math.Max(0, originalBytes);
        long byFraction = (long)(OriginalBytes * Math.Max(0, maxGrowthFraction));
        MaxGrowthBytes = Math.Max(byFraction, minAbsoluteGrowth);
    }

    public long RemainingBytes => Math.Max(0, MaxGrowthBytes - _reserved);

    public bool CanAfford(long estimatedBytes) => _reserved + Math.Max(0, estimatedBytes) <= MaxGrowthBytes;

    /// <summary>Reserve budget; returns false (and reserves nothing) if it would overflow.</summary>
    public bool TryReserve(long estimatedBytes)
    {
        estimatedBytes = Math.Max(0, estimatedBytes);
        if (_reserved + estimatedBytes > MaxGrowthBytes) return false;
        _reserved += estimatedBytes;
        return true;
    }
}
