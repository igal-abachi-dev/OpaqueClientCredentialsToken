using OpaqueClientCredentialsTokenTester.Settings;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

public sealed class ClientStore
{
    private readonly IReadOnlyDictionary<string, ClientConfig> _clients;

    public ClientStore(Microsoft.Extensions.Options.IOptions<ClientsOptions> opt)
        => _clients = opt.Value;

    public bool TryGet(string clientId, out ClientConfig client)
        => _clients.TryGetValue(clientId, out client!);

    public bool VerifySecret(ClientConfig client, string clientSecret)
    {
        byte[] storedHash = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(client.SecretHash)) return false;

        // Stored: base64(SHA256(UTF8(secret)))
        try
        {
            var b = Convert.FromBase64String(client.SecretHash);

            if (storedHash.Length != 32) return false;
            
                storedHash = b;


                var inputHash = SHA256.HashData(Encoding.UTF8.GetBytes(clientSecret));
                return CryptographicOperations.FixedTimeEquals(inputHash, storedHash);
            
        }
        catch { /* ignore */ }


        return false;

    }

}
