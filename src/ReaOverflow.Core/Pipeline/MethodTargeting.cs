using dnlib.DotNet;

namespace ReaOverflow.Core.Pipeline;

/// <summary>
/// Decides which methods a body-rewriting pass (P1 string-encryption, P2 opaque predicates,
/// P3 MBA) is allowed to touch.
///
/// Compiler-generated <b>async/iterator state machines are off-limits</b>: the C# compiler emits
/// a <c>MoveNext</c> whose integer <c>&lt;&gt;1__state</c> field drives a fragile jump table, and
/// injecting control flow (P2) or rewriting integer constants (P3) into that body corrupts the
/// dispatch. Observed on real async-heavy code (filehound's IndexManager): task double-completion
/// (<c>InvalidOperationException</c>) and <c>NullReferenceException</c>s even though the transforms
/// are algebraic/behaviour-preserving in ordinary methods.
///
/// We skip two things: the generated state-machine type's methods (<c>MoveNext</c>,
/// <c>SetStateMachine</c>) and the user's own async/iterator "kickoff" method (the compiler marks
/// it with <c>[AsyncStateMachine]</c>/<c>[IteratorStateMachine]</c>). Ordinary compiler-generated
/// code that is NOT a state machine — lambda/closure display classes — is left rewritable, since
/// those bodies are plain methods that the passes handle correctly.
/// </summary>
internal static class MethodTargeting
{
    private const string AsyncStateMachineIface = "System.Runtime.CompilerServices.IAsyncStateMachine";
    private const string EnumeratorIface = "System.Collections.IEnumerator";

    /// <summary>True if <paramref name="m"/> is (or belongs to) a compiler-generated state machine
    /// and must not have its IL body rewritten.</summary>
    public static bool IsStateMachineBody(MethodDef m)
    {
        // Kickoff method: the user's async/iterator method, tagged by the compiler.
        foreach (CustomAttribute ca in m.CustomAttributes)
        {
            string name = ca.AttributeType?.Name ?? string.Empty;
            if (name == "AsyncStateMachineAttribute" || name == "IteratorStateMachineAttribute")
                return true;
        }

        // Generated state-machine type: MoveNext / SetStateMachine live here. Require both the
        // [CompilerGenerated] marker and a state-machine interface so ordinary generated types
        // (lambda closures, anonymous types) stay rewritable.
        TypeDef? t = m.DeclaringType;
        if (t is null || !IsCompilerGenerated(t)) return false;
        foreach (InterfaceImpl ii in t.Interfaces)
        {
            string? fullName = ii.Interface?.FullName;
            if (fullName == AsyncStateMachineIface || fullName == EnumeratorIface)
                return true;
        }
        return false;
    }

    private static bool IsCompilerGenerated(TypeDef t)
    {
        foreach (CustomAttribute ca in t.CustomAttributes)
            if (ca.AttributeType?.Name == "CompilerGeneratedAttribute") return true;
        return false;
    }
}
