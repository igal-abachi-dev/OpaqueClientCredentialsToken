//(RSA-4096, OAEP-SHA256, AES-GCM, Protocol Binding).

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace OpaqueClientCredentialsTokenTester.Helpers
{
    public static class RsaAesHybridCapsule
    {
        // -----------------------------------------------------------------
        // CONFIGURATION: JWE Compatible Defaults
        // -----------------------------------------------------------------
        public const int RsaKeySizeBits = 4096; //3072 faster
        private static readonly RSAEncryptionPadding RsaWrapPadding = RSAEncryptionPadding.OaepSHA256;

        private const int AesKeySize = 32;   // 256-bit AES
        private const int NonceSize = 12;   // 96-bit Nonce (GCM Standard)
        private const int TagSize = 16;   // 128-bit Tag (GCM Standard)

        // Binds the encrypted data to this specific protocol version.
        // Prevents algorithm confusion attacks.
        private static readonly byte[] ProtocolAad = Encoding.ASCII.GetBytes("v1:RSA-OAEP-256+A256GCM");

        // -----------------------------------------------------------------
        // KEYS
        // -----------------------------------------------------------------
        public static (string privateKeyPem, string publicKeyPem) GenerateRsaKeys()
        {
            using var rsa = RSA.Create(RsaKeySizeBits);
            return (rsa.ExportPkcs8PrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
        }

        // -----------------------------------------------------------------
        // ENCRYPT
        // -----------------------------------------------------------------
        public static string Encrypt(string plaintext, string publicKeyPem)
        {
            if (string.IsNullOrEmpty(plaintext)) return string.Empty;

            // 1. Generate secrets
            byte[] aesKey = RandomNumberGenerator.GetBytes(AesKeySize);
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);

            // We declare these outside to ensure we can ZeroMemory them in finally
            byte[] plainBytes = null;

            try
            {
                // 2. Encrypt Content (AES-GCM)
                plainBytes = Encoding.UTF8.GetBytes(plaintext);
                byte[] cipherBytes = new byte[plainBytes.Length];
                byte[] tag = new byte[TagSize];

                using (var aes = new AesGcm(aesKey, TagSize))
                {
                    aes.Encrypt(nonce, plainBytes, cipherBytes, tag, ProtocolAad);
                }

                // 3. Encrypt/Wrap AES Key (RSA-OAEP)
                byte[] encryptedKey;
                using (var rsa = RSA.Create())
                {
                    rsa.ImportFromPem(publicKeyPem);
                    if (rsa.KeySize != 4096) throw new ArgumentException("Only 4096-bit keys allowed");
                    encryptedKey = rsa.Encrypt(aesKey, RsaWrapPadding);// Always 512 bytes for 4096-bit key
                }

                // 4. Pack into Binary Format
                // Layout: [EncKey (512)] [Nonce (12)] [Tag (16)] [Ciphertext (?)]
                int totalLen = encryptedKey.Length + NonceSize + TagSize + cipherBytes.Length;
                byte[] blob = new byte[totalLen];
                int offset = 0;

                Buffer.BlockCopy(encryptedKey, 0, blob, offset, encryptedKey.Length); offset += encryptedKey.Length;//512
                Buffer.BlockCopy(nonce, 0, blob, offset, NonceSize); offset += NonceSize;
                Buffer.BlockCopy(tag, 0, blob, offset, TagSize); offset += TagSize;
                Buffer.BlockCopy(cipherBytes, 0, blob, offset, cipherBytes.Length);

                return Base64UrlEncode(blob);
            }
            finally
            {
                // Ensure secrets are wiped even if RSA throws an exception
                CryptographicOperations.ZeroMemory(aesKey);
                if (plainBytes != null) CryptographicOperations.ZeroMemory(plainBytes);
            }
        }

        // -----------------------------------------------------------------
        // DECRYPT
        // -----------------------------------------------------------------
        public static string Decrypt(string package, string privateKeyPem)
        {
            if (string.IsNullOrEmpty(package)) return string.Empty;

            byte[] blob;
            try
            {
                blob = Base64UrlDecode(package);
            }
            catch (FormatException) { throw new ArgumentException("Invalid package format"); }


            if (blob.Length < (512 + NonceSize + TagSize)) throw new ArgumentException("Invalid Package");

            ReadOnlySpan<byte> encKeySpan = blob.AsSpan(0, 512);
            ReadOnlySpan<byte> nonceSpan = blob.AsSpan(512, NonceSize);
            ReadOnlySpan<byte> tagSpan = blob.AsSpan(512 + NonceSize, TagSize);
            ReadOnlySpan<byte> cipherSpan = blob.AsSpan(512 + NonceSize + TagSize);


            // 1. Prepare Buffer for AES Key
            byte[] aesKey = new byte[AesKeySize];

            // Generate a "Fake" key. If RSA fails, we use this.
            // This ensures the code path takes the same time to fail (Mitigate Bleichenbacher Timing Attack)
            byte[] fakeKey = RandomNumberGenerator.GetBytes(AesKeySize);

            byte[] plainBytes = null;

            try
            {
                // 2. Unwrap Key (RSA) - Zero Allocation method
                using (var rsa = RSA.Create())
                {
                    rsa.ImportFromPem(privateKeyPem);

                    // Try to decrypt. Do NOT throw if it fails.
                    bool rsaSuccess = rsa.TryDecrypt(encKeySpan, aesKey, RsaWrapPadding, out int bytesWritten);

                    bool isValid = rsaSuccess && (bytesWritten == AesKeySize);

                    // CONSTANT TIME SWAP (Logic):
                    // If Valid: aesKey remains the real key.
                    // If Invalid: Overwrite aesKey with fakeKey.
                    if (!isValid)
                    {
                        // We proceed with the fake key.
                        // AES-GCM will verify the tag against this fake key and fail securely (Tag Mismatch).
                        // The attacker sees the exact same "Decryption failed" error and timing is correct.
                        fakeKey.CopyTo(aesKey, 0);
                    }
                }

                // 3. Decrypt Content (AES-GCM)
                plainBytes = new byte[cipherSpan.Length];
                using (var aes = new AesGcm(aesKey, TagSize))
                {
                    // If RSA failed, this fails on FakeKey.
                    // If RSA succeeded but data is bad, this fails on RealKey.
                    aes.Decrypt(nonceSpan, cipherSpan, tagSpan, plainBytes, ProtocolAad);
                }

                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (CryptographicException)
            {
                // Swallow exact details to prevent Oracle attacks
                throw new ArgumentException("Decryption failed.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(aesKey);
                CryptographicOperations.ZeroMemory(fakeKey);
                if (plainBytes != null) CryptographicOperations.ZeroMemory(plainBytes);
            }
        }

        // -----------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------
        private static string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        private static byte[] Base64UrlDecode(string input)
        {
            string incoming = input
                .Replace('-', '+')
                .Replace('_', '/');

            switch (input.Length % 4)
            {
                case 2: incoming += "=="; break;
                case 3: incoming += "="; break;
            }
            return Convert.FromBase64String(incoming);
        }
    }
}