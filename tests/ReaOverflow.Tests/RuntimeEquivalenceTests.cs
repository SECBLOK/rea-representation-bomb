using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using ReaOverflow.Core.Analysis;
using ReaOverflow.Core.Passes;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Report;
using Xunit;

namespace ReaOverflow.Tests;

/// <summary>
/// Validation gates that run on a Defender-active Windows host.
///  - Identity pipeline: executed in-memory (proves pipeline + ALC harness produce runnable output).
///  - P1 string encryption: structural reload + byte-level plaintext check (NOT executed here,
///    because Windows Defender/AMSI blocks loading the obfuscated image — see DOCS; real CLR
///    execution of the obfuscated build is validated in Linux via Docker in scripts/linux-run.sh).
/// </summary>
public class RuntimeEquivalenceTests
{
    private const string SecretPlaintext = "api-token-9F3A-DO-NOT-SHIP-PLAINTEXT";

    [Fact]
    public void Identity_Pipeline_Executes_And_Is_Equivalent()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        string baseline = AssemblyRunner.RunToString(original);
        Assert.Contains("secret=" + SecretPlaintext, baseline);

        var options = new ProtectionOptions { Seed = 0xA11CE };
        (ProtectionReport _, byte[] identity) = Protector.ProtectToBytes(original, options,
            Array.Empty<IProtectionPass>());

        string identityOut = AssemblyRunner.RunToString(identity);
        Assert.Equal(baseline, identityOut);
    }

    [Fact]
    public void StringEncryption_HidesStrings_AndStaysStructurallyValid()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xA11CE };
        (ProtectionReport report, byte[] protectedBytes) =
            Protector.ProtectToBytes(original, options, new IProtectionPass[] { new StringEncryptionPass() });

        // Independent dnlib re-parse: the writer produced a well-formed, decodable assembly.
        StructuralValidator.Result v = StructuralValidator.Validate(protectedBytes);
        Assert.True(v.Ok, "structural issues: " + string.Join(" | ", v.Issues));
        Assert.True(v.IsILOnly);
        Assert.True(v.HasEntryPoint);

        Assert.True(ContainsUtf16(original, SecretPlaintext), "sample should leak plaintext");
        Assert.False(ContainsUtf16(protectedBytes, SecretPlaintext), "protected must NOT contain plaintext");
        Assert.True(report.GrowthFraction < 0.25, $"growth {report.GrowthFraction:P1} exceeded budget");
    }

    [Fact]
    public void OpaquePredicate_Executes_And_Is_Equivalent()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        string baseline = AssemblyRunner.RunToString(original);

        var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xA11CE };
        (ProtectionReport report, byte[] protectedBytes) =
            Protector.ProtectToBytes(original, options, new IProtectionPass[] { new OpaquePredicatePass() });

        // P2 adds no crypto, so the CLR can load it in-memory even on this Defender-active host:
        // run it and prove the opaque-predicate rewrite is behaviour-preserving.
        string protectedOut = AssemblyRunner.RunToString(protectedBytes);
        Assert.Equal(baseline, protectedOut);
        Assert.True(report.Passes[0].Counters["methods_guarded"] > 0, "expected methods to be guarded");
    }

    [Fact]
    public void ControlFlowAndMba_PreserveAsyncStateMachine()
    {
        // Regression: P2 (opaque predicates) + P3 (MBA) must leave compiler-generated async state
        // machines untouched. Before the MethodTargeting guard these rewrote the generated MoveNext
        // and corrupted the <>1__state dispatch (task double-completion / NRE on real async code).
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        string baseline = AssemblyRunner.RunToString(original);
        Assert.Contains("async-sum=385", baseline); // the sample's async method actually ran

        var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xA11CE };
        (ProtectionReport report, byte[] protectedBytes) = Protector.ProtectToBytes(original, options,
            new IProtectionPass[] { new OpaquePredicatePass(), new MbaSubstitutionPass() });

        // Both invasive passes did real work on ordinary methods...
        Assert.True(report.Passes[0].Counters["methods_guarded"] > 0, "expected methods to be guarded");
        Assert.True(report.Passes[1].Counters["constants_substituted"] > 0, "expected constants substituted");
        // ...yet the async state machine survives and the whole app stays behaviour-equivalent.
        string protectedOut = AssemblyRunner.RunToString(protectedBytes);
        Assert.Equal(baseline, protectedOut);
    }

    [Fact]
    public void MbaSubstitution_PreservesBranches_AcrossSeeds()
    {
        // Regression for the branch-overflow bug: inserting MBA sequences mid-body pushed short
        // branches (br.s/bgt.s) past their ±127-byte reach and corrupted loop entry/back edges
        // (seen as IndexOutOfRange in filehound's BoundedHeap). The sample has a long, constant-dense
        // loop for exactly this; the bug is seed-dependent, so sweep seeds and require every one to
        // stay behaviour-equivalent (incl. the heap whose SiftUp(0) indexes [-1] if its guard is lost).
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        string baseline = AssemblyRunner.RunToString(original);
        Assert.Contains("heap-min=1", baseline);
        Assert.Contains("longloop=", baseline);

        for (ulong seed = 0; seed < 32; seed++)
        {
            var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = seed };
            (ProtectionReport _, byte[] protectedBytes) = Protector.ProtectToBytes(original, options,
                new IProtectionPass[] { new MbaSubstitutionPass() });
            string protectedOut = AssemblyRunner.RunToString(protectedBytes);
            Assert.True(baseline == protectedOut, $"MBA diverged at seed {seed}:\n--- expected ---\n{baseline}\n--- got ---\n{protectedOut}");
        }
    }

    [Fact]
    public void OpaquePredicate_AddsInstructions_AndStaysStructurallyValid()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        ReaModel.Result before = ReaModel.Analyze(original);

        var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xA11CE };
        (ProtectionReport _, byte[] protectedBytes) =
            Protector.ProtectToBytes(original, options, new IProtectionPass[] { new OpaquePredicatePass() });

        StructuralValidator.Result v = StructuralValidator.Validate(protectedBytes);
        Assert.True(v.Ok, "structural issues: " + string.Join(" | ", v.Issues));
        Assert.True(v.IsILOnly);
        Assert.True(v.HasEntryPoint);

        // More instructions and more call edges → strictly higher modelled REA charge.
        ReaModel.Result after = ReaModel.Analyze(protectedBytes);
        Assert.True(after.TotalChargeBytes > before.TotalChargeBytes,
            $"charge did not grow: {before.TotalChargeBytes} -> {after.TotalChargeBytes}");
    }

    [Fact]
    public void MetadataInflation_CrossesBudget_ExecutesEquivalently_AndStaysSmall()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        string baseline = AssemblyRunner.RunToString(original);

        var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xA11CE };
        (ProtectionReport report, byte[] protectedBytes) =
            Protector.ProtectToBytes(original, options, new IProtectionPass[] { new MetadataInflationPass() });

        // Dead inflation methods are never JIT'd, so the real program still runs identically.
        string protectedOut = AssemblyRunner.RunToString(protectedBytes);
        Assert.Equal(baseline, protectedOut);

        // The thesis: modelled REA charge crosses 64 MiB while disk growth stays small (<1 MB).
        ReaModel.Result r = ReaModel.Analyze(protectedBytes);
        Assert.True(r.CrossesBudget, $"modelled charge {r.TotalChargeBytes:N0} did not cross 64 MiB");
        Assert.True(report.GrowthBytes < 1_000_000, $"disk grew too much: {report.GrowthBytes:N0} bytes");
        Assert.True(r.TotalChargeBytes / (double)report.GrowthBytes > 100,
            "charge-to-disk ratio should be superlinear (that's the whole point)");
    }

    [Fact]
    public void MetadataInflation_Maximum_PlantsRankCap_AndNotTheRetiredNestingCap()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xBEEF };
        (ProtectionReport _, byte[] protectedBytes) =
            Protector.ProtectToBytes(original, options, new IProtectionPass[] { new MetadataInflationPass() });

        ReaModel.Result r = ReaModel.Analyze(protectedBytes);
        // Array-rank is the one structural cap-attack measured to bite REA — still planted.
        Assert.Contains(r.TrippedCaps, c => c.Contains("rank"));
        // The deep-nesting lever was cut (measured no-op at any depth), so we no longer plant it.
        Assert.DoesNotContain(r.TrippedCaps, c => c.Contains("nesting"));
        Assert.False(r.JtdPresent);
        Assert.StartsWith("partial/degraded", r.PredictedStatus);
    }

    [Fact]
    public void DecoyArchetype_InjectsBelievableDecoys_AndExecutesEquivalently()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        string baseline = AssemblyRunner.RunToString(original);
        ReaModel.Result before = ReaModel.Analyze(original);

        var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xA11CE };
        (ProtectionReport report, byte[] protectedBytes) =
            Protector.ProtectToBytes(original, options, new IProtectionPass[] { new DecoyArchetypePass() });

        // Decoys are never invoked (and the P/Invoke never binds), so the real program is unchanged.
        string protectedOut = AssemblyRunner.RunToString(protectedBytes);
        Assert.Equal(baseline, protectedOut);

        StructuralValidator.Result v = StructuralValidator.Validate(protectedBytes);
        Assert.True(v.Ok, "structural issues: " + string.Join(" | ", v.Issues));

        // Ten archetypes (security + functional) + the SubsystemBroker hub + >=1 P/Invoke decoy landed.
        Assert.Equal(11, report.Passes[0].Counters["decoy_types"]);
        Assert.True(report.Passes[0].Counters["decoy_pinvokes"] >= 1);

        // Interconnection: decoy->decoy call edges + real->decoy edges were injected (the misdirection win).
        Assert.True(report.Passes[0].Counters["decoy_cross_edges"] >= 7, "expected dense decoy->decoy call edges");
        Assert.True(report.Passes[0].Counters["real_to_decoy_edges"] >= 1, "expected real code wired into decoys");

        // Believable decoy content is actually present in the image (would mislead an LLM reader).
        // Type/member names live in #Strings as UTF-8; ldstr literals live in #US as UTF-16.
        Assert.True(ContainsUtf8(protectedBytes, "LicenseRing"), "expected a LicenseRing decoy type");
        Assert.True(ContainsUtf8(protectedBytes, "SubsystemBroker"), "expected the SubsystemBroker hub type");
        Assert.True(ContainsUtf16(protectedBytes, "PBKDF2-HMAC-SHA256"), "expected KdfVault decoy strings");
        // Functional (non-security) archetypes broaden analyst-goal coverage beyond the licensing framing.
        Assert.True(ContainsUtf8(protectedBytes, "ProtocolRouter"), "expected a functional ProtocolRouter decoy type");

        // Extra types/methods/strings → higher modelled REA charge.
        ReaModel.Result after = ReaModel.Analyze(protectedBytes);
        Assert.True(after.TotalChargeBytes > before.TotalChargeBytes);
    }

    [Fact]
    public void MbaSubstitution_Executes_And_Is_Equivalent()
    {
        byte[] original = File.ReadAllBytes(SampleLocator.HelloTargetDll());
        string baseline = AssemblyRunner.RunToString(original);
        ReaModel.Result before = ReaModel.Analyze(original);

        var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xA11CE };
        (ProtectionReport report, byte[] protectedBytes) =
            Protector.ProtectToBytes(original, options, new IProtectionPass[] { new MbaSubstitutionPass() });

        // The MBA identity must hold at runtime: identical output proves C was reconstructed exactly.
        string protectedOut = AssemblyRunner.RunToString(protectedBytes);
        Assert.Equal(baseline, protectedOut);

        Assert.True(report.Passes[0].Counters["constants_substituted"] > 0, "expected constants to be substituted");
        ReaModel.Result after = ReaModel.Analyze(protectedBytes);
        Assert.True(after.TotalChargeBytes > before.TotalChargeBytes);
    }

    internal static bool ContainsUtf16(byte[] haystack, string needle)
        => Contains(haystack, Encoding.Unicode.GetBytes(needle));

    internal static bool ContainsUtf8(byte[] haystack, string needle)
        => Contains(haystack, Encoding.UTF8.GetBytes(needle));

    private static bool Contains(byte[] haystack, byte[] pat)
    {
        for (int i = 0; i + pat.Length <= haystack.Length; i++)
        {
            int j = 0;
            while (j < pat.Length && haystack[i + j] == pat[j]) j++;
            if (j == pat.Length) return true;
        }
        return false;
    }
}

internal static class SampleLocator
{
    public static string HelloTargetDll()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ReaOverflow.slnx")))
            dir = dir.Parent;
        if (dir is null) throw new FileNotFoundException("repo root (ReaOverflow.slnx) not found");
        string path = Path.Combine(dir.FullName, "samples", "HelloTarget", "bin", "Release", "net8.0", "HelloTarget.dll");
        if (!File.Exists(path))
            throw new FileNotFoundException($"sample not built; run: dotnet build samples/HelloTarget -c Release\nexpected: {path}");
        return path;
    }
}

internal static class AssemblyRunner
{
    /// <summary>Load an assembly from bytes, run its entry point, and capture stdout.</summary>
    public static string RunToString(byte[] assemblyBytes)
    {
        var alc = new AssemblyLoadContext("reaoverflow-run", isCollectible: true);
        TextWriter originalOut = Console.Out;
        var sw = new StringWriter();
        try
        {
            Assembly asm = alc.LoadFromStream(new MemoryStream(assemblyBytes));
            MethodInfo ep = asm.EntryPoint ?? throw new InvalidOperationException("no entry point");
            object?[]? args = ep.GetParameters().Length == 1 ? new object?[] { Array.Empty<string>() } : null;
            Console.SetOut(sw);
            try { ep.Invoke(null, args); }
            catch (TargetInvocationException tie) { throw tie.InnerException ?? tie; }
            return sw.ToString();
        }
        finally
        {
            Console.SetOut(originalOut);
            alc.Unload();
        }
    }
}
