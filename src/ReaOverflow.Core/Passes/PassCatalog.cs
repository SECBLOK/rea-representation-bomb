using System.Collections.Generic;
using ReaOverflow.Core.Pipeline;

namespace ReaOverflow.Core.Passes;

/// <summary>The ordered registry of protection passes. Passes are added here as they land.</summary>
public static class PassCatalog
{
    public static IReadOnlyList<IProtectionPass> All() => new IProtectionPass[]
    {
        // Order matters: encrypt strings → inject opaque/decoys → inflate metadata last.
        new StringEncryptionPass(),   // P1
        new OpaquePredicatePass(),    // P2
        new MbaSubstitutionPass(),    // P3
        new DecoyArchetypePass(),     // P4
        new MetadataInflationPass(),  // P5
        new RawMetadataPass(),        // P6 (gated;      opt-in via --passes P6)
        new SelfSealPass(),           // P7 (gated;      opt-in via --passes P7)
        new RuntimeDecoyTelemetryPass(), // P8 (decorative; opt-in via --passes P8)
        new RepresentationBombPass(),    // P9 (gated;      opt-in via --passes P9)
    };
}
