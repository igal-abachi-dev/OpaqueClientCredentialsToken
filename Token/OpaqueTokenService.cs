namespace OpaqueClientCredentialsTokenTester.Token
{
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.Json;
    using Microsoft.AspNetCore.WebUtilities;

    public sealed class OpaqueTokenService
    {
        private const int NonceSize = 12; // AesGcm supports 12-byte nonce 
        private const int TagSize = 16; // 16-byte tag (best portability) 

        private static readonly byte[] ProtocolAad = Encoding.ASCII.GetBytes("v1:opaque-a256gcm");

        private readonly KeyManager _keys;

        public OpaqueTokenService(KeyManager keys) => _keys = keys;

        public string Encrypt(TokenPayload payload)
        {
            var kid = _keys.CurrentKeyId;
            var key = _keys.GetKeyBytes(kid);

            var json = JsonSerializer.SerializeToUtf8Bytes(payload);

            var kidBytes = Encoding.UTF8.GetBytes(kid);
            if (kidBytes.Length > byte.MaxValue)
                throw new InvalidOperationException("kid is too long.");

            var header = BuildHeader(ver: 1, kidBytes);

            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var tag = new byte[TagSize];
            var ciphertext = new byte[json.Length];

            // AAD binds protocol + header to the ciphertext, preventing header tampering.
            var aad = Concat(ProtocolAad, header);

            using var gcm = new AesGcm(key, TagSize);
            gcm.Encrypt(nonce, json, ciphertext, tag, aad);

            var tokenBytes = Concat(header, nonce, tag, ciphertext);
            return WebEncoders.Base64UrlEncode(tokenBytes);
        }

        public bool TryDecrypt(string token, out TokenPayload? payload, out string error)
        {
            payload = null;

            byte[] bytes;
            try { bytes = WebEncoders.Base64UrlDecode(token); }
            catch { error = "invalid_token_format"; return false; }

            if (bytes.Length < 2 + NonceSize + TagSize)
            {
                error = "invalid_token_format";
                return false;
            }

            var ver = bytes[0];
            if (ver != 1)
            {
                error = "unsupported_token_version";
                return false;
            }

            var kidLen = bytes[1];
            var minLen = 2 + kidLen + NonceSize + TagSize;
            if (bytes.Length < minLen)
            {
                error = "invalid_token_format";
                return false;
            }

            var kidBytes = bytes.AsSpan(2, kidLen).ToArray();
            var kid = Encoding.UTF8.GetString(kidBytes);

            byte[] key;
            try { key = _keys.GetKeyBytes(kid); }
            catch
            {
                error = "unknown_kid";
                return false;
            }

            var header = BuildHeader(ver, kidBytes);
            var aad = Concat(ProtocolAad, header);

            var offset = 2 + kidLen;

            var nonce = bytes.AsSpan(offset, NonceSize).ToArray();
            offset += NonceSize;

            var tag = bytes.AsSpan(offset, TagSize).ToArray();
            offset += TagSize;

            var ciphertext = bytes.AsSpan(offset).ToArray();
            var plaintext = new byte[ciphertext.Length];

            try
            {
                using var gcm = new AesGcm(key, TagSize);
                gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            }
            catch (CryptographicException)
            {
                error = "invalid_token";
                return false;
            }

            try
            {
                payload = JsonSerializer.Deserialize<TokenPayload>(plaintext);
                if (payload is null)
                {
                    error = "invalid_token";
                    return false;
                }
            }
            catch
            {
                error = "invalid_token";
                return false;
            }

            error = "";
            return true;
        }

        private static byte[] BuildHeader(byte ver, byte[] kidBytes)
        {
            var header = new byte[2 + kidBytes.Length];
            header[0] = ver;
            header[1] = (byte)kidBytes.Length;
            Buffer.BlockCopy(kidBytes, 0, header, 2, kidBytes.Length);
            return header;
        }

        private static byte[] Concat(params byte[][] parts)
        {
            var len = parts.Sum(p => p.Length);
            var buf = new byte[len];
            var off = 0;
            foreach (var p in parts)
            {
                Buffer.BlockCopy(p, 0, buf, off, p.Length);
                off += p.Length;
            }
            return buf;
        }
    }

}
