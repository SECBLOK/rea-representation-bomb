using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Pipeline;

/// <summary>Orchestrates load → ordered passes → write, filling the honesty report.</summary>
public static class Protector
{
    /// <summary>
    /// Protect raw assembly bytes and return the protected bytes. Used by tests and any
    /// caller that wants to avoid writing a standalone PE to disk (which AV may quarantine).
    /// </summary>
    public static (ProtectionReport Report, byte[] Bytes) ProtectToBytes(
        byte[] input, ProtectionOptions options, IReadOnlyList<IProtectionPass> passes)
    {
        var report = new ProtectionReport { OriginalBytes = input.LongLength };
        var module = ModuleDefMD.Load(input);
        try
        {
            var budget = new SizeBudget(input.LongLength, options.MaxGrowthFraction, options.MinAbsoluteGrowth);
            var ctx = new ProtectionContext(module, options, budget, report);

            // Any metadata rewrite breaks an existing strong-name signature.
            if (module.Assembly is { } asm && (asm.HasPublicKey || asm.PublicKey is { IsNullOrEmpty: false }))
                report.Warnings.Add(options.SignKeyPath is not null
                    ? "input was strong-named; its original signature is replaced by the --sign key."
                    : "input is strong-named — protection invalidates its strong-name signature; re-sign with "
                        + "--sign <key.snk> (or verify the P7 seal instead). Authenticode is likewise invalidated.");

            foreach (IProtectionPass pass in passes)
            {
                bool defaultOn = pass.DefaultFor(options.Intensity);
                if (!options.IsEnabled(pass.Id, defaultOn)) continue;

                PassReport pr = report.AddPass(pass.Id, pass.Name, pass.Safety, pass.Status);
                pass.Run(ctx, pr);
                pr.Applied = true;
            }

            // Post-write passes (P7 self-seal) edit bytes AFTER signing, which breaks the signature.
            if (options.SignKeyPath is not null && ctx.PostWriteTransforms.Count > 0)
                report.Warnings.Add("--sign with a post-write pass (e.g. P7 self-seal): the post-write edit runs "
                    + "after signing and invalidates the strong-name signature — drop P7 when signing, or verify the seal.");

            using var ms = new MemoryStream();
            WriteModule(module, ms, ctx.WriterCustomizations, options.SignKeyPath);
            byte[] bytes = ms.ToArray();
            foreach (var transform in ctx.PostWriteTransforms)
                bytes = transform(bytes);
            report.ProtectedBytes = bytes.LongLength;
            return (report, bytes);
        }
        finally
        {
            module.Dispose();
        }
    }

    public static ProtectionReport Protect(string inputPath, string outputPath,
        ProtectionOptions options, IReadOnlyList<IProtectionPass> passes)
    {
        byte[] raw = File.ReadAllBytes(inputPath);
        (ProtectionReport report, byte[] bytes) = ProtectToBytes(raw, options, passes);
        report.OriginalBytes = new FileInfo(inputPath).Length;
        File.WriteAllBytes(outputPath, bytes);
        report.ProtectedBytes = new FileInfo(outputPath).Length;
        return report;
    }

    private static void WriteModule(ModuleDefMD module, Stream dest,
        IReadOnlyList<System.Action<ModuleWriterOptionsBase>> customizations, string? signKeyPath)
    {
        StrongNameKey? snk = signKeyPath is null ? null : new StrongNameKey(signKeyPath);
        if (module.IsILOnly)
        {
            var opts = new ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance };
            foreach (var c in customizations) c(opts);
            if (snk is not null) opts.InitializeStrongNameSigning(module, snk);
            module.Write(dest, opts);
        }
        else
        {
            var opts = new NativeModuleWriterOptions(module, optimizeImageSize: true) { Logger = DummyLogger.NoThrowInstance };
            foreach (var c in customizations) c(opts);
            if (snk is not null) opts.InitializeStrongNameSigning(module, snk);
            module.NativeWrite(dest, opts);
        }
    }
}
