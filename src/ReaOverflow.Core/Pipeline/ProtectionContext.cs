using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Pipeline;

/// <summary>
/// Shared state threaded through every pass: the loaded module, the project PRNG, options,
/// the size budget, the report, and helpers for importing BCL members and for the single
/// injected runtime helper type that passes hang their methods/fields on.
/// </summary>
public sealed class ProtectionContext
{
    private readonly Importer _importer;
    private TypeDef? _runtimeType;
    private readonly string _rtNamespace;
    private readonly string _rtName;

    public ModuleDefMD Module { get; }
    public SeededPrng Prng { get; }
    public ProtectionOptions Options { get; }
    public SizeBudget Budget { get; }
    public ProtectionReport Report { get; }

    /// <summary>
    /// Passes that work at the metadata/stream layer (P6) register here; <see cref="Protector"/>
    /// applies each to the writer options just before emitting the module.
    /// </summary>
    public List<Action<ModuleWriterOptionsBase>> WriterCustomizations { get; } = new();

    /// <summary>
    /// Passes that must patch the final image bytes (P7 self-seal) register here; each runs in order
    /// on the written bytes and returns the transformed bytes.
    /// </summary>
    public List<Func<byte[], byte[]>> PostWriteTransforms { get; } = new();

    public ProtectionContext(ModuleDefMD module, ProtectionOptions options, SizeBudget budget, ProtectionReport report)
    {
        Module = module;
        Options = options;
        Budget = budget;
        Report = report;
        Prng = new SeededPrng(options.Seed);
        _importer = new Importer(module);
        var ns = Prng.Fork("rt-namespace");
        _rtNamespace = ns.NextIdentifier(ns.Next(6, 11));
        _rtName = ns.NextIdentifier(ns.Next(6, 11));
    }

    /// <summary>The single injected static helper type (lazily created, static = sealed+abstract).</summary>
    public TypeDef RuntimeType
    {
        get
        {
            if (_runtimeType is null)
            {
                _runtimeType = new TypeDefUser(_rtNamespace, _rtName, Module.CorLibTypes.Object.TypeDefOrRef)
                {
                    Attributes = dnlib.DotNet.TypeAttributes.NotPublic | dnlib.DotNet.TypeAttributes.AutoLayout
                                 | dnlib.DotNet.TypeAttributes.AnsiClass | dnlib.DotNet.TypeAttributes.Abstract
                                 | dnlib.DotNet.TypeAttributes.Sealed | dnlib.DotNet.TypeAttributes.BeforeFieldInit,
                };
                Module.Types.Add(_runtimeType);
            }
            return _runtimeType;
        }
    }

    public ICorLibTypes Cor => Module.CorLibTypes;

    public IMethod ImportMethod(Type declaringType, string name, params Type[] paramTypes)
    {
        MethodInfo mi = declaringType.GetMethod(name, BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance,
                            binder: null, types: paramTypes, modifiers: null)
                        ?? throw new InvalidOperationException($"BCL method not found: {declaringType}.{name}");
        return _importer.Import(mi);
    }

    public IMethod ImportGetter(Type declaringType, string propertyName)
    {
        PropertyInfo pi = declaringType.GetProperty(propertyName, BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance)
                          ?? throw new InvalidOperationException($"BCL property not found: {declaringType}.{propertyName}");
        return _importer.Import(pi.GetGetMethod() ?? throw new InvalidOperationException($"no getter: {propertyName}"));
    }

    public ITypeDefOrRef ImportType(Type t) => _importer.ImportAsTypeSig(t).ToTypeDefOrRef();
    public TypeSig ImportTypeSig(Type t) => _importer.ImportAsTypeSig(t);

    /// <summary>Methods with IL bodies that belong to the user's code (not our injected type),
    /// excluding compiler-generated async/iterator state machines whose <c>MoveNext</c> dispatch a
    /// body-rewriting pass would corrupt (see <see cref="MethodTargeting"/>).</summary>
    public IEnumerable<MethodDef> UserMethods()
    {
        foreach (TypeDef type in Module.GetTypes().ToList())
        {
            if (ReferenceEquals(type, _runtimeType)) continue;
            foreach (MethodDef m in type.Methods)
                if (m.HasBody && m.Body.Instructions.Count > 0 && !MethodTargeting.IsStateMachineBody(m))
                    yield return m;
        }
    }
}
