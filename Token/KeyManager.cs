using Microsoft.Extensions.Options;
using OpaqueClientCredentialsTokenTester.Settings;
using System.Security.Cryptography;
using System.Text;

namespace OpaqueClientCredentialsTokenTester.Token
{

    public sealed class KeyManager
    {
        private readonly TokenSettings _settings;

        public KeyManager(IOptions<TokenSettings> opt)
        {
            _settings = opt.Value;

            if (string.IsNullOrWhiteSpace(_settings.CurrentKeyId))
                throw new InvalidOperationException("TokenSettings.CurrentKeyId is required.");

            if (_settings.Keys is null || _settings.Keys.Count == 0)
                throw new InvalidOperationException("TokenSettings.Keys must contain at least one key.");
        }

        public string CurrentKeyId => _settings.CurrentKeyId;

        public byte[] GetKeyBytes(string kid)
        {
            if (!_settings.Keys.TryGetValue(kid, out var b64))
                throw new KeyNotFoundException($"Unknown kid '{kid}'.");

            var key = Convert.FromBase64String(b64);
            if (key.Length != 32) // AES-256
                throw new InvalidOperationException($"Key '{kid}' must be 32 bytes (base64 of 32 raw bytes).");

            return key;
        }
    }
}

/*
 
 public sealed class KeyManager
   {
       private readonly TokenSettings _settings;
   
       public KeyManager(Microsoft.Extensions.Options.IOptions<TokenSettings> opt)
       {
           _settings = opt.Value;
   
           if (string.IsNullOrWhiteSpace(_settings.CurrentKeyId))
               throw new InvalidOperationException("TokenSettings.CurrentKeyId is required.");
   
           // In prod, Keys must come from env vars / secret store.
           if (_settings.Keys is null || _settings.Keys.Count == 0)
               throw new InvalidOperationException("TokenSettings.Keys is empty. Inject keys via environment variables.");
       }
   
       public string CurrentKeyId => _settings.CurrentKeyId;
   
       public byte[] GetKeyBytes(string kid)
       {
           if (!_settings.Keys.TryGetValue(kid, out var b64))
               throw new KeyNotFoundException($"Unknown kid '{kid}'.");
   
           var key = Convert.FromBase64String(b64);
           if (key.Length != 32)
               throw new InvalidOperationException($"Key '{kid}' must be 32 bytes (AES-256).");
   
           return key;
       }
   }
   
 */