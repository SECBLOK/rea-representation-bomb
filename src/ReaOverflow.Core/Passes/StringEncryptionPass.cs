using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Prng;
using ReaOverflow.Core.Report;

namespace ReaOverflow.Core.Passes;

/// <summary>
/// P1 — String encryption. Replaces every <c>ldstr "literal"</c> in user code with a call to a
/// seeded decryptor injected into the runtime helper type; the ciphertext (base64) is what lands
/// in the <c>#US</c> heap. REA never runs the decryptor, so plaintext is unrecoverable statically,
/// and the richest LLM signal (readable strings) is removed. The keystream is deliberately simple:
/// its job is static opacity, not cryptographic secrecy (the key is in the binary either way).
/// </summary>
public sealed class StringEncryptionPass : IProtectionPass
{
    public string Id => "P1";
    public string Name => "String encryption";
    public SafetyClass Safety => SafetyClass.Safe;
    public EvidenceStatus Status => EvidenceStatus.Verified;
    public bool DefaultFor(Intensity intensity) => true;

    public void Run(ProtectionContext ctx, PassReport report)
    {
        int key = unchecked((int)ctx.Prng.Fork("p1-strings").NextUInt32());

        // Snapshot user methods BEFORE injecting the decryptor (so we never rewrite it).
        List<MethodDef> targets = ctx.UserMethods().ToList();

        MethodDef decrypt = BuildDecryptor(ctx, key);

        int sites = 0;
        long added = 0;
        foreach (MethodDef m in targets)
        {
            IList<Instruction> ins = m.Body.Instructions;
            for (int i = 0; i < ins.Count; i++)
            {
                if (ins[i].OpCode.Code == Code.Ldstr && ins[i].Operand is string s && s.Length > 0)
                {
                    string cipher = Encrypt(s, key);
                    added += Math.Max(0, cipher.Length - s.Length);
                    if (!ctx.Budget.TryReserve(cipher.Length))
                    {
                        report.Notes.Add("size budget reached; remaining strings left in cleartext");
                        goto done;
                    }
                    ins[i].Operand = cipher;                                  // ldstr now holds ciphertext
                    ins.Insert(i + 1, OpCodes.Call.ToInstruction(decrypt));   // ...decoded at runtime
                    i++;                                                      // skip inserted call
                    sites++;
                }
            }
            m.Body.OptimizeMacros();
        }
    done:
        report.Count("strings_encrypted", sites);
        report.EstimatedBytesAdded = added + 220; // decryptor method overhead
        report.Notes.Add($"keystream key=0x{key:X8} (static-opacity XOR, non-cryptographic)");
    }

    /// <summary>Mirror of the emitted IL: <c>b[i] ^= (byte)(key + i)</c>. Reversible.</summary>
    internal static string Encrypt(string plain, int key)
    {
        byte[] b = Encoding.UTF8.GetBytes(plain);
        for (int i = 0; i < b.Length; i++)
            b[i] ^= (byte)(key + i);
        return Convert.ToBase64String(b);
    }

    private static MethodDef BuildDecryptor(ProtectionContext ctx, int key)
    {
        var sig = MethodSig.CreateStatic(ctx.Cor.String, ctx.Cor.String);
        var m = new MethodDefUser(ctx.Prng.Fork("p1-name").NextIdentifier(14), sig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            // Assembly (internal): the decryptor is called from user methods in other types, so it
            // must be accessible assembly-wide — a Private helper throws MethodAccessException at runtime.
            dnlib.DotNet.MethodAttributes.Assembly | dnlib.DotNet.MethodAttributes.Static | dnlib.DotNet.MethodAttributes.HideBySig);
        ctx.RuntimeType.Methods.Add(m);

        IMethod fromB64 = ctx.ImportMethod(typeof(Convert), nameof(Convert.FromBase64String), typeof(string));
        IMethod getUtf8 = ctx.ImportGetter(typeof(Encoding), nameof(Encoding.UTF8));
        IMethod getString = ctx.ImportMethod(typeof(Encoding), nameof(Encoding.GetString), typeof(byte[]));

        var body = new CilBody { InitLocals = true, MaxStack = 8 };
        var bLoc = new Local(new SZArraySig(ctx.Cor.Byte));
        var iLoc = new Local(ctx.Cor.Int32);
        body.Variables.Add(bLoc);
        body.Variables.Add(iLoc);

        var check = OpCodes.Ldloc.ToInstruction(iLoc);     // CHECK: label
        var loopStart = OpCodes.Ldloc.ToInstruction(bLoc); // LOOP: label

        IList<Instruction> il = body.Instructions;
        il.Add(OpCodes.Ldarg_0.ToInstruction());
        il.Add(OpCodes.Call.ToInstruction(fromB64));
        il.Add(OpCodes.Stloc.ToInstruction(bLoc));
        il.Add(OpCodes.Ldc_I4_0.ToInstruction());
        il.Add(OpCodes.Stloc.ToInstruction(iLoc));
        il.Add(OpCodes.Br.ToInstruction(check));
        // LOOP: b[i] = b[i] ^ (byte)(key + i)
        il.Add(loopStart);                                 // ldloc b
        il.Add(OpCodes.Ldloc.ToInstruction(iLoc));         // i
        il.Add(OpCodes.Ldloc.ToInstruction(bLoc));         // b
        il.Add(OpCodes.Ldloc.ToInstruction(iLoc));         // i
        il.Add(OpCodes.Ldelem_U1.ToInstruction());         // b[i]
        il.Add(Instruction.CreateLdcI4(key));              // key
        il.Add(OpCodes.Ldloc.ToInstruction(iLoc));         // i
        il.Add(OpCodes.Add.ToInstruction());               // key+i
        il.Add(OpCodes.Conv_U1.ToInstruction());           // (byte)(key+i)
        il.Add(OpCodes.Xor.ToInstruction());
        il.Add(OpCodes.Conv_U1.ToInstruction());
        il.Add(OpCodes.Stelem_I1.ToInstruction());         // b[i] = ...
        il.Add(OpCodes.Ldloc.ToInstruction(iLoc));         // i++
        il.Add(OpCodes.Ldc_I4_1.ToInstruction());
        il.Add(OpCodes.Add.ToInstruction());
        il.Add(OpCodes.Stloc.ToInstruction(iLoc));
        // CHECK: i < b.Length
        il.Add(check);                                     // ldloc i
        il.Add(OpCodes.Ldloc.ToInstruction(bLoc));
        il.Add(OpCodes.Ldlen.ToInstruction());
        il.Add(OpCodes.Conv_I4.ToInstruction());
        il.Add(OpCodes.Blt.ToInstruction(loopStart));
        // return Encoding.UTF8.GetString(b)
        il.Add(OpCodes.Call.ToInstruction(getUtf8));
        il.Add(OpCodes.Ldloc.ToInstruction(bLoc));
        il.Add(OpCodes.Callvirt.ToInstruction(getString));
        il.Add(OpCodes.Ret.ToInstruction());

        m.Body = body;
        body.OptimizeMacros();
        body.OptimizeBranches();
        return m;
    }
}
