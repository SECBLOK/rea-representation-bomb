using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using ReaOverflow.Core.Analysis;
using ReaOverflow.Core.Passes;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Cli;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 0) { PrintUsage(); return 1; }
        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "protect" => CmdProtect(args.Skip(1).ToArray()),
                "analyze" => CmdAnalyze(args.Skip(1).ToArray()),
                "verify" => CmdVerify(args.Skip(1).ToArray()),
                "list" => CmdList(),
                "-h" or "--help" or "help" => CmdHelp(),
                _ => Fail($"unknown command '{args[0]}'"),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            return 2;
        }
    }

    private static int CmdProtect(string[] a)
    {
        var p = new ArgParser(a);
        string input = p.Positional(0) ?? throw new ArgumentException("missing <input assembly>");
        string output = p.Option("-o", "--out") ?? throw new ArgumentException("missing -o <output>");
        var options = new ProtectionOptions();

        string? intensity = p.Option("--intensity");
        if (intensity is not null)
            options.Intensity = Enum.Parse<Intensity>(intensity, ignoreCase: true);

        string? seed = p.Option("--seed");
        var (resolvedSeed, wasRandom) = SeedPolicy.Resolve(seed);
        options.Seed = resolvedSeed;
        Console.Error.WriteLine(wasRandom
            ? $"seed: 0x{resolvedSeed:X16} (random per build; pass --seed 0x{resolvedSeed:X16} to reproduce)"
            : $"seed: 0x{resolvedSeed:X16} (explicit)");

        string? passes = p.Option("--passes");
        if (passes is not null)
            options.EnabledPasses = passes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                          .Select(s => s.ToUpperInvariant()).ToHashSet();

        string? p6variant = p.Option("--p6-variant");
        if (p6variant is not null)
            options.RawMetadataVariant = p6variant.ToLowerInvariant() switch
            {
                "dup" or "duplicate" or "duplicatestream" => RawMetadataVariant.DuplicateStream,
                "manystreams" or "many" or "streams" => RawMetadataVariant.ManyStreams,
                "badname" or "nonprintable" or "ctrl" => RawMetadataVariant.NonPrintableStreamName,
                _ => throw new ArgumentException($"unknown --p6-variant '{p6variant}' (use dup|manystreams|badname)"),
            };

        string? growth = p.Option("--max-growth");
        if (growth is not null) options.MaxGrowthFraction = double.Parse(growth.TrimEnd('%'), CultureInfo.InvariantCulture) / (growth.Contains('%') ? 100.0 : 1.0);

        string? sign = p.Option("--sign");
        if (sign is not null)
        {
            if (!File.Exists(sign)) throw new ArgumentException($"strong-name key not found: {sign}");
            options.SignKeyPath = sign;
        }

        bool emitB64 = p.Option("--b64") is not null;
        ProtectionReport report;
        if (emitB64)
        {
            // Emit base64 text (AV-safe) instead of a standalone PE, for Linux/Docker validation.
            byte[] raw = File.ReadAllBytes(input);
            (report, byte[] bytes) = Protector.ProtectToBytes(raw, options, PassCatalog.All());
            report.OriginalBytes = raw.LongLength;
            File.WriteAllText(output, Convert.ToBase64String(bytes));
        }
        else
        {
            report = Protector.Protect(input, output, options, PassCatalog.All());
        }

        if (p.Option("--json") is not null)
            EmitJson(new
            {
                tool = "reaoverflow", command = "protect",
                output = Path.GetFileName(output),
                seed = $"0x{options.Seed:X16}", intensity = options.Intensity.ToString(),
                originalBytes = report.OriginalBytes, protectedBytes = report.ProtectedBytes,
                growthBytes = report.GrowthBytes, growthFraction = report.GrowthFraction,
                signed = options.SignKeyPath is not null,
                warnings = report.Warnings,
                verified = report.Passes.Count(pr => pr.Status == EvidenceStatus.Verified),
                designedFor = report.Passes.Count(pr => pr.Status == EvidenceStatus.DesignedFor),
                passes = report.Passes.Select(pr => new
                {
                    id = pr.Id, name = pr.Name, safety = pr.Safety.ToString(), status = pr.Status.ToString(),
                    counters = pr.Counters, notes = pr.Notes,
                }),
            });
        else
            PrintReport(report, options);
        return 0;
    }

    private static int CmdAnalyze(string[] a)
    {
        var p = new ArgParser(a);
        string input = p.Positional(0) ?? throw new ArgumentException("missing <assembly>");
        byte[] bytes = File.ReadAllBytes(input);
        ReaModel.Result r = ReaModel.Analyze(bytes);
        if (p.Option("--json") is not null)
            EmitJson(new
            {
                tool = "reaoverflow", command = "analyze",
                target = Path.GetFileName(input), fileBytes = r.FileBytes,
                // Honesty: every field below is a MODELLED prediction, not measured against real REA.
                measuredAgainstRea = r.MeasuredAgainstRea,
                disclaimer = ReaModel.Disclaimer,
                modelledChargeBytes = r.TotalChargeBytes, budgetBytes = ReaModel.RepresentationBudgetBytes,
                budgetFraction = r.BudgetFraction,
                modelledCrossesBudget = r.CrossesBudget,
                modelledAnyHardStop = r.AnyHardStop,
                jtdPresent = r.JtdPresent, snapshotRefusal = r.SnapshotRefusal,
                trippedCaps = r.TrippedCaps, modelledPredictedStatus = r.PredictedStatus,
                // MEASURED (not modelled): P6 duplicate-stream / >64-stream metadata denial vs rea@6.7.0.
                measuredReaMetadataDenied = r.ReaMetadataDenied, measuredDenialReason = r.DenialReason,
                breakdown = r.Breakdown.Select(c => new { category = c.Category, bytes = c.Bytes, items = c.Items }),
            });
        else
            PrintReaModel(input, r);
        return 0;
    }

    private static void PrintReaModel(string path, ReaModel.Result r)
    {
        Console.WriteLine($"ReaOverflow — analyze (MODELLED REA ManagedDecodeBudget — optimistic, DesignedFor)");
        Console.WriteLine($"  target: {Path.GetFileName(path)}  ({r.FileBytes:N0} bytes on disk)");
        Console.WriteLine($"  modelled charge: {r.TotalChargeBytes:N0} bytes  ({r.BudgetFraction:P1} of REA's 64 MiB budget)");
        Console.WriteLine("  breakdown:");
        foreach (ReaModel.Charge c in r.Breakdown)
            Console.WriteLine($"      {c.Category,-38} {c.Bytes,15:N0} B   ({c.Items:N0} items)");
        Console.WriteLine($"  MODELLED crosses 64 MiB budget: {(r.CrossesBudget ? "YES" : "no")}  (model prediction — NOT measured against REA)");
        if (r.TrippedCaps.Count > 0)
        {
            Console.WriteLine("  modelled caps tripped:");
            foreach (string cap in r.TrippedCaps) Console.WriteLine($"      - {cap}");
        }
        if (r.JtdPresent) Console.WriteLine("  #JTD stream: PRESENT (structural fact only — MEASURED no-op vs real REA, not a hard stop)");
        if (r.ReaMetadataDenied)
            Console.WriteLine($"  P6 metadata denial: PRESENT ({r.DenialReason}) — MEASURED vs rea@6.7.0 and 6.9.0: metadata reported "
                + "malformed with 0 members across all managed inspectors; exit 0 (denial, not a crash); .NET 8 CLR loads+runs it.");
        Console.WriteLine($"  modelled REA status: {r.PredictedStatus}");
        Console.WriteLine();
        Console.WriteLine("  ── honesty ──");
        Console.WriteLine("  " + ReaModel.Disclaimer.Replace(". ", ".\n  "));
    }

    private static int CmdVerify(string[] a)
    {
        var p = new ArgParser(a);
        string orig = p.Positional(0) ?? throw new ArgumentException("missing <original assembly>");
        string prot = p.Positional(1) ?? throw new ArgumentException("missing <protected assembly>");
        string? argStr = p.Option("--args");
        string[]? entryArgs = argStr?.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        byte[] origBytes = File.ReadAllBytes(orig);
        byte[] protBytes = File.ReadAllBytes(prot);
        Verifier.Report rep = Verifier.Verify(origBytes, protBytes, entryArgs);

        // Opt-in independent decompiler cross-check (spawns ilspycmd; best-effort).
        IlSpyCrossCheck.Result? ilspy = p.Option("--ilspy") is not null
            ? IlSpyCrossCheck.Run(origBytes, protBytes)
            : null;

        if (p.Option("--json") is not null)
        {
            var gates = rep.Gates.Select(g => new
            {
                name = g.Name, outcome = g.Outcome.ToString().ToLowerInvariant(),
                critical = g.Critical, detail = g.Detail,
            }).ToList();
            if (ilspy is not null)
                gates.Add(new { name = "ilspy-degradation", outcome = ilspy.Outcome, critical = false, detail = ilspy.Detail });
            EmitJson(new
            {
                tool = "reaoverflow", command = "verify",
                original = Path.GetFileName(orig), protectedAssembly = Path.GetFileName(prot),
                ok = rep.Ok, exitCode = rep.Ok ? 0 : 3,
                gates,
            });
            return rep.Ok ? 0 : 3;
        }

        Console.WriteLine("ReaOverflow — verify (TECH-SPEC §6 gates)");
        Console.WriteLine($"  original : {Path.GetFileName(orig)}");
        Console.WriteLine($"  protected: {Path.GetFileName(prot)}");
        foreach (Verifier.Gate g in rep.Gates)
        {
            string mark = g.Outcome switch
            {
                Verifier.Outcome.Pass => "PASS",
                Verifier.Outcome.Fail => "FAIL",
                Verifier.Outcome.Blocked => "BLOCKED",
                _ => "SKIP",
            };
            Console.WriteLine($"  [{mark,-7}] {g.Name}{(g.Critical ? "" : " (non-critical)")}");
            Console.WriteLine($"            {g.Detail}");
        }
        if (ilspy is not null)
        {
            Console.WriteLine($"  [{ilspy.Outcome.ToUpperInvariant(),-7}] ilspy-degradation (non-critical, external)");
            Console.WriteLine($"            {ilspy.Detail}");
        }
        Console.WriteLine($"  => {(rep.Ok ? "OK — no critical gate failed" : "NOT CLEAR — a critical gate FAILED")}");
        Console.WriteLine("  honesty: BLOCKED gates were not provable on this host, not passes. The rea-budget");
        Console.WriteLine("           gate is a MODELLED design target (DesignedFor), NOT measured resistance:");
        Console.WriteLine("           validated against rea@6.7.0/6.9.0 the model OVER-PREDICTS — real REA decoded");
        Console.WriteLine("           protected assemblies completely (no exhaustion; #JTD/nesting caps did not bite).");
        Console.WriteLine("           Measured effect is a ~20-23% token tax + decoys. For ground truth run the");
        Console.WriteLine("           empirical gate: scripts/rea-token-gate.ps1 (or .sh). See docs/TECH-SPEC.md.");
        return rep.Ok ? 0 : 3;
    }

    private static void PrintReport(ProtectionReport r, ProtectionOptions o)
    {
        Console.WriteLine($"ReaOverflow — protected (seed=0x{o.Seed:X16}, intensity={o.Intensity})");
        Console.WriteLine($"  size: {r.OriginalBytes:N0} -> {r.ProtectedBytes:N0} bytes ({r.GrowthFraction:P1})");
        if (o.SignKeyPath is not null) Console.WriteLine($"  strong-name signed with {Path.GetFileName(o.SignKeyPath)}");
        foreach (string w in r.Warnings) Console.WriteLine($"  WARNING: {w}");
        if (r.Passes.Count == 0) { Console.WriteLine("  passes: none (identity round-trip)"); return; }
        foreach (PassReport pr in r.Passes)
        {
            string counters = pr.Counters.Count == 0 ? "" : " [" + string.Join(", ", pr.Counters.Select(kv => $"{kv.Key}={kv.Value}")) + "]";
            Console.WriteLine($"  {pr.Id} {pr.Name} ({pr.Safety}/{pr.Status}){counters}");
            foreach (string note in pr.Notes) Console.WriteLine($"      - {note}");
        }
        int verified = r.Passes.Count(pr => pr.Status == EvidenceStatus.Verified);
        int designed = r.Passes.Count(pr => pr.Status == EvidenceStatus.DesignedFor);
        Console.WriteLine($"  honesty: {verified} Verified (proven on a target), {designed} DesignedFor (modelled); "
            + "REA-charge figures are modelled estimates — run 'verify' / 'analyze' and see docs/TECH-SPEC.md.");
    }

    private static int CmdList()
    {
        Console.WriteLine("ReaOverflow — protection passes (order = pipeline order)");
        foreach (IProtectionPass p in PassCatalog.All())
        {
            string policy = p.DefaultFor(Intensity.Stealth) ? "default (all intensities)"
                : p.DefaultFor(Intensity.Balanced) ? "default at balanced+"
                : p.DefaultFor(Intensity.Maximum) ? "default at maximum"
                : "opt-in only (gated)";
            Console.WriteLine($"  {p.Id}  {p.Name,-40} {p.Safety}/{p.Status,-11} [{policy}]");
        }
        Console.WriteLine("  run a subset with:  protect <in> -o <out> --passes P1,P6,...");
        Console.WriteLine("  gated passes (P6/P7/P8) run ONLY when named explicitly.");
        return 0;
    }

    private static void EmitJson(object dto)
        => Console.WriteLine(JsonSerializer.Serialize(dto, JsonOpts));

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    private static int CmdHelp() { PrintUsage(); return 0; }

    private static int Fail(string msg) { Console.Error.WriteLine("error: " + msg); PrintUsage(); return 1; }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            ReaOverflow — counter-REA .NET protector

            usage:
              reaoverflow protect <in.dll> -o <out.dll> [--intensity stealth|balanced|maximum]
                                  [--seed 0xHEX] [--passes P1,P2,...] [--max-growth 25%]
                                  [--sign key.snk] [--b64] [--p6-variant dup|manystreams|badname]
              reaoverflow analyze <assembly> [--json]
              reaoverflow verify  <orig> <prot> [--args "<entry args>"] [--ilspy] [--json]
              reaoverflow list                   # show all passes, safety/status, and defaults

            --json on protect/analyze/verify emits machine-readable output for CI (verify exits 3 on failure).

            passes: P1 strings · P2 opaque · P3 MBA · P4 decoys · P5 metadata-inflation
                    P6 raw-metadata* · P7 self-seal* · P8 runtime-telemetry*   (* gated: opt-in only)
            """);
    }
}

/// <summary>Minimal positional + option arg parser.</summary>
internal sealed class ArgParser
{
    private readonly List<string> _positional = new();
    private readonly Dictionary<string, string> _options = new(StringComparer.OrdinalIgnoreCase);

    public ArgParser(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg.StartsWith('-'))
            {
                string? value = (i + 1 < args.Length && !args[i + 1].StartsWith('-')) ? args[++i] : "true";
                _options[arg] = value;
            }
            else _positional.Add(arg);
        }
    }

    public string? Positional(int index) => index < _positional.Count ? _positional[index] : null;

    public string? Option(params string[] names)
    {
        foreach (string n in names)
            if (_options.TryGetValue(n, out string? v)) return v;
        return null;
    }
}
