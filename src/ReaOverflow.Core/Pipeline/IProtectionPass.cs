using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Pipeline;

public interface IProtectionPass
{
    /// <summary>Stable short id, e.g. "P1".</summary>
    string Id { get; }

    string Name { get; }

    SafetyClass Safety { get; }

    /// <summary>Honesty status for the report (Verified once we've proven it on a target).</summary>
    EvidenceStatus Status { get; }

    /// <summary>Whether this pass runs by default at the given intensity.</summary>
    bool DefaultFor(Intensity intensity);

    /// <summary>Apply the transform, mutating <see cref="ProtectionContext.Module"/>.</summary>
    void Run(ProtectionContext ctx, PassReport report);
}
