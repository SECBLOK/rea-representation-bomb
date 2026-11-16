using System;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;

namespace ReaOverflow.Core.Pipeline;

/// <summary>
/// Loads an assembly from bytes into a collectible context, runs its entry point, and captures
/// stdout — without touching disk. Every failure (including the antivirus
/// <c>BadImageFormatException</c> that fires when a host flags an obfuscated image) is caught and
/// reported rather than thrown, so callers can distinguish "ran and differed" from "couldn't run here".
/// </summary>
public static class RuntimeRunner
{
    public sealed record RunResult(bool Ran, string Output, string? Error);

    public static RunResult TryRun(byte[] assemblyBytes, string[]? entryArgs = null)
    {
        var alc = new AssemblyLoadContext("reaoverflow-verify", isCollectible: true);
        TextWriter originalOut = Console.Out;
        var sw = new StringWriter();
        try
        {
            Assembly asm = alc.LoadFromStream(new MemoryStream(assemblyBytes));
            MethodInfo? ep = asm.EntryPoint;
            if (ep is null) return new RunResult(false, "", "no entry point");

            object?[]? args = ep.GetParameters().Length == 1
                ? new object?[] { entryArgs ?? Array.Empty<string>() }
                : null;

            Console.SetOut(sw);
            try { ep.Invoke(null, args); }
            catch (TargetInvocationException tie) { throw tie.InnerException ?? tie; }
            return new RunResult(true, sw.ToString(), null);
        }
        catch (Exception ex)
        {
            return new RunResult(false, sw.ToString(), $"{ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            Console.SetOut(originalOut);
            alc.Unload();
        }
    }
}
