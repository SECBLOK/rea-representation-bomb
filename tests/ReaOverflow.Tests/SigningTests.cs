using System.IO;
using System.Security.Cryptography;
using dnlib.DotNet;
using ReaOverflow.Core.Passes;
using ReaOverflow.Core.Pipeline;
using ReaOverflow.Core.Report;
using Xunit;

namespace ReaOverflow.Tests;

public class SigningTests
{
    private static byte[] Sample() => File.ReadAllBytes(SampleLocator.HelloTargetDll());

    private static IProtectionPass[] Stack() => new IProtectionPass[]
    {
        new OpaquePredicatePass(), new MbaSubstitutionPass(),
        new DecoyArchetypePass(), new MetadataInflationPass(),
    };

    [Fact]
    public void Protect_WithSign_ProducesStrongNamedOutput_ThatStillRuns()
    {
        string baseline = AssemblyRunner.RunToString(Sample());
        string snk = WriteTempSnk();
        try
        {
            var options = new ProtectionOptions { Intensity = Intensity.Maximum, Seed = 0xA11CE, SignKeyPath = snk };
            (ProtectionReport _, byte[] prot) = Protector.ProtectToBytes(Sample(), options, Stack());

            using (var m = ModuleDefMD.Load(prot))
            {
                Assert.True(m.Assembly.HasPublicKey, "protected output should carry a public key");
                Assert.False(m.Assembly.PublicKey.IsNullOrEmpty);
                Assert.True(m.Assembly.PublicKey.Data.Length >= 160, "expected a 1024-bit SN public key blob");
            }

            // .NET Core doesn't enforce SN verification at load, so the signed build still runs identically.
            Assert.Equal(baseline, AssemblyRunner.RunToString(prot));
        }
        finally { File.Delete(snk); }
    }

    [Fact]
    public void Sign_WithPostWriteSeal_WarnsSignatureIsInvalidated()
    {
        string snk = WriteTempSnk();
        try
        {
            var options = new ProtectionOptions
            {
                Seed = 0xA11CE, SignKeyPath = snk,
                EnabledPasses = new System.Collections.Generic.HashSet<string> { "P7" },
            };
            (ProtectionReport report, _) = Protector.ProtectToBytes(Sample(), options, new IProtectionPass[] { new SelfSealPass() });
            Assert.Contains(report.Warnings, w => w.Contains("invalidates the strong-name"));
        }
        finally { File.Delete(snk); }
    }

    private static string WriteTempSnk()
    {
        string path = Path.Combine(Path.GetTempPath(), "reaoverflow-" + System.Guid.NewGuid().ToString("N") + ".snk");
        File.WriteAllBytes(path, GenerateSnk());
        return path;
    }

    /// <summary>Builds a valid 1024-bit CAPI PRIVATEKEYBLOB (.snk) from a fresh RSA key.</summary>
    private static byte[] GenerateSnk()
    {
        using var rsa = RSA.Create(1024);
        RSAParameters k = rsa.ExportParameters(includePrivateParameters: true);

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write((byte)0x07);          // bType = PRIVATEKEYBLOB
        w.Write((byte)0x02);          // bVersion
        w.Write((ushort)0);           // reserved
        w.Write((uint)0x2400);        // aiKeyAlg = CALG_RSA_SIGN
        w.Write((uint)0x32415352);    // magic "RSA2"
        w.Write((uint)1024);          // bitlen
        uint e = 0; foreach (byte b in k.Exponent) e = (e << 8) | b;
        w.Write(e);                   // pubexp (uint32 LE)
        w.Write(Le(k.Modulus, 128));
        w.Write(Le(k.P, 64));
        w.Write(Le(k.Q, 64));
        w.Write(Le(k.DP, 64));
        w.Write(Le(k.DQ, 64));
        w.Write(Le(k.InverseQ, 64));
        w.Write(Le(k.D, 128));
        w.Flush();
        return ms.ToArray();
    }

    // .NET RSAParameters are big-endian minimal; CAPI wants fixed-length little-endian.
    private static byte[] Le(byte[]? bigEndian, int len)
    {
        var d = new byte[len];
        if (bigEndian is null) return d;
        for (int i = 0; i < bigEndian.Length && i < len; i++) d[i] = bigEndian[bigEndian.Length - 1 - i];
        return d;
    }
}
