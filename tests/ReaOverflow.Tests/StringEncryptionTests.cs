using System;
using System.Text;
using ReaOverflow.Core.Passes;
using Xunit;

namespace ReaOverflow.Tests;

public class StringEncryptionTests
{
    // Independent re-implementation of the decrypt side to prove Encrypt is reversible
    // and that the emitted-IL formula (b[i] ^= (byte)(key+i)) round-trips.
    private static string Decrypt(string cipherB64, int key)
    {
        byte[] b = Convert.FromBase64String(cipherB64);
        for (int i = 0; i < b.Length; i++)
            b[i] ^= (byte)(key + i);
        return Encoding.UTF8.GetString(b);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("api-token-9F3A-DO-NOT-SHIP-PLAINTEXT")]
    [InlineData("unicode: café ☕ 日本語")]
    [InlineData("a longer string with spaces, punctuation! and 1234567890")]
    public void Encrypt_Then_Decrypt_RoundTrips(string plain)
    {
        const int key = unchecked((int)0xDEADBEEF);
        string cipher = StringEncryptionPass.Encrypt(plain, key);
        Assert.Equal(plain, Decrypt(cipher, key));
    }

    [Fact]
    public void Ciphertext_DoesNotContainPlaintext()
    {
        const string plain = "SUPER-SECRET-VALUE";
        string cipher = StringEncryptionPass.Encrypt(plain, 1234);
        Assert.DoesNotContain("SECRET", cipher, StringComparison.Ordinal);
    }
}
