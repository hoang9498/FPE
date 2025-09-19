using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Fpe;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;
using System.Text;

public class FpeExample
{
    public static void Main(string[] args)
    {
        // Alphabet: letters + digits (62 characters)
        string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        // AES-128 key (16 bytes exactly)
        byte[] key = Encoding.UTF8.GetBytes("1234567890abcdef");

        // Non-secret tweak (can be anything, or empty)
        byte[] tweak = Encoding.UTF8.GetBytes("Some-Tweak");

        // Example plaintext (must use only characters from alphabet)
        string plaintext = "BX69l1QESRcKQY8";

        // Convert plaintext string -> byte[]
        byte[] ptBytes = plaintext.Select(c => (byte)alphabet.IndexOf(c)).ToArray();

        // Create FPE engine (FF1 with AES)
        FpeFf1Engine fpe = new FpeFf1Engine(new AesEngine());
        FpeParameters parameters = new FpeParameters(new KeyParameter(key), alphabet.Length, tweak);

        // Encrypt
        fpe.Init(true, parameters);
        byte[] ctBytes = new byte[ptBytes.Length];
        fpe.ProcessBlock(ptBytes, 0, ptBytes.Length, ctBytes, 0);
        string ciphertext = new string(ctBytes.Select(i => alphabet[i]).ToArray());

        Console.WriteLine($"Original:  {plaintext}");
        Console.WriteLine($"Encrypted: {ciphertext}");
        // Decrypt
        fpe.Init(false, parameters);
        byte[] decBytes = new byte[ctBytes.Length];
        fpe.ProcessBlock(ctBytes, 0, ctBytes.Length, decBytes, 0);
        string decrypted = new string(decBytes.Select(i => alphabet[i]).ToArray());

        Console.WriteLine($"Decrypted: {decrypted}");
    }
}
// To run this example, you need to install the BouncyCastle package:
// dotnet add package BouncyCastle.NetCore --version 2.2.1