using System;
using System.Diagnostics;
using System.IO;

namespace ReaOverflow.Cli;

/// <summary>
/// Opt-in independent cross-check: decompiles the original and protected assemblies with ilspycmd
/// (a real third-party decompiler, not our dnlib model) and reports how much harder the protected
/// output is to read — more lines to wade through, fewer readable string literals, or an outright
/// decompiler error/timeout. It writes temp DLLs and spawns a process, so it lives in the CLI and is
/// off unless <c>--ilspy</c> is passed. Every failure (tool missing, AV blocking the temp write,
/// timeout) is reported honestly as "could not run", never as a pass.
/// </summary>
internal static class IlSpyCrossCheck
{
    private const int TimeoutMs = 90_000;

    public sealed record Result(bool Ran, string Outcome, string Detail);

    public static Result Run(byte[] original, byte[] protectedBytes)
    {
        if (!IsAvailable())
            return new Result(false, "skipped",
                "ilspycmd not found on PATH — install with: dotnet tool install -g ilspycmd");

        string dir = Path.Combine(Path.GetTempPath(), "reaoverflow-ilspy-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(dir);
            string origPath = Path.Combine(dir, "orig.dll");
            string protPath = Path.Combine(dir, "prot.dll");
            File.WriteAllBytes(origPath, original);
            File.WriteAllBytes(protPath, protectedBytes);

            (string oText, bool oErr, bool oTimeout) = Decompile(origPath);
            (string pText, bool pErr, bool pTimeout) = Decompile(protPath);

            if (oTimeout || string.IsNullOrEmpty(oText))
                return new Result(false, "blocked", "ilspycmd could not decompile the ORIGINAL here, so no baseline to compare");

            int oLines = CountLines(oText), pLines = CountLines(pText);
            int oStrings = Count(oText, '"') / 2, pStrings = Count(pText, '"') / 2;

            bool degraded = pTimeout || pErr || pLines > oLines || pStrings < oStrings;
            string note = pTimeout ? "protected decompile TIMED OUT (decompiler overwhelmed); "
                        : pErr ? "protected decompile reported errors; " : "";
            string detail = $"{note}decompiled lines {oLines}→{pLines}, string literals {oStrings}→{pStrings} "
                            + "(independent ilspycmd decompiler)";
            return new Result(true, degraded ? "pass" : "skipped", detail);
        }
        catch (Exception ex)
        {
            return new Result(false, "blocked",
                "ilspycmd cross-check could not run (e.g. antivirus blocked the temp DLL): " + ex.Message);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best-effort cleanup */ }
        }
    }

    private static bool IsAvailable()
    {
        try
        {
            (string _, bool err, bool timeout) = RunProcess("--version");
            return !err && !timeout;
        }
        catch { return false; }
    }

    private static (string Text, bool Errored, bool TimedOut) Decompile(string dllPath)
        => RunProcess($"\"{dllPath}\"");

    private static (string Text, bool Errored, bool TimedOut) RunProcess(string ilspyArgs)
    {
        bool win = OperatingSystem.IsWindows();
        var psi = new ProcessStartInfo
        {
            FileName = win ? "cmd.exe" : "ilspycmd",
            Arguments = win ? $"/c ilspycmd {ilspyArgs}" : ilspyArgs,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("failed to start ilspycmd");
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        if (!proc.WaitForExit(TimeoutMs))
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            return (stdout, true, true);
        }
        bool errored = proc.ExitCode != 0
                       || stderr.Contains("error", StringComparison.OrdinalIgnoreCase)
                       || stdout.Contains("/* Error", StringComparison.Ordinal);
        return (stdout, errored, false);
    }

    private static int CountLines(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        int n = 1;
        foreach (char c in s) if (c == '\n') n++;
        return n;
    }

    private static int Count(string s, char ch)
    {
        int n = 0;
        foreach (char c in s) if (c == ch) n++;
        return n;
    }
}
