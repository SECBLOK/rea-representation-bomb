using System.Collections.Generic;
using ReaOverflow.Core.Pipeline;

namespace ReaOverflow.Core.Report;

/// <summary>Honesty status: did we empirically prove this, or is it designed-for (modelled)?</summary>
public enum EvidenceStatus
{
    Verified,
    DesignedFor,
}

public sealed class PassReport
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public SafetyClass Safety { get; init; }
    public EvidenceStatus Status { get; init; } = EvidenceStatus.DesignedFor;
    public bool Applied { get; set; }
    public long EstimatedBytesAdded { get; set; }
    public Dictionary<string, long> Counters { get; } = new();
    public List<string> Notes { get; } = new();

    public void Count(string key, long delta = 1)
        => Counters[key] = Counters.TryGetValue(key, out var v) ? v + delta : delta;
}

public sealed class ProtectionReport
{
    public long OriginalBytes { get; set; }
    public long ProtectedBytes { get; set; }
    public long GrowthBytes => ProtectedBytes - OriginalBytes;
    public double GrowthFraction => OriginalBytes > 0 ? (double)GrowthBytes / OriginalBytes : 0;
    public List<PassReport> Passes { get; } = new();

    /// <summary>Cross-cutting warnings surfaced once (e.g. protection invalidated a strong-name signature).</summary>
    public List<string> Warnings { get; } = new();

    public PassReport AddPass(string id, string name, SafetyClass safety, EvidenceStatus status)
    {
        var r = new PassReport { Id = id, Name = name, Safety = safety, Status = status };
        Passes.Add(r);
        return r;
    }
}
