using System.Collections.Generic;
using dnlib.DotNet;

namespace ReaOverflow.Core.Pipeline;

/// <summary>
/// Re-parses protected bytes with an independent dnlib reader and decodes every method body.
/// Proves the writer produced a well-formed, parseable assembly without executing it (so it
/// works even when antivirus blocks loading the obfuscated image on the host).
/// </summary>
public static class StructuralValidator
{
    public sealed record Result(bool Ok, bool IsILOnly, bool HasEntryPoint, int MethodsDecoded, IReadOnlyList<string> Issues);

    public static Result Validate(byte[] assemblyBytes)
    {
        var issues = new List<string>();
        int decoded = 0;
        bool ilOnly;
        bool hasEntry;
        var module = ModuleDefMD.Load(assemblyBytes);
        try
        {
            ilOnly = module.IsILOnly;
            hasEntry = module.EntryPoint is not null;
            foreach (TypeDef type in module.GetTypes())
            {
                foreach (MethodDef m in type.Methods)
                {
                    if (!m.HasBody) continue;
                    try
                    {
                        // Touch instructions + operands to force full decode.
                        foreach (var instr in m.Body.Instructions)
                            _ = instr.Operand;
                        decoded++;
                    }
                    catch (System.Exception ex)
                    {
                        issues.Add($"{m.FullName}: {ex.GetType().Name}: {ex.Message}");
                    }
                }
            }
        }
        finally
        {
            module.Dispose();
        }
        return new Result(issues.Count == 0, ilOnly, hasEntry, decoded, issues);
    }
}
