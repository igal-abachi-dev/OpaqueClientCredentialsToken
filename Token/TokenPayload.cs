using System.Text.Json.Serialization;

namespace OpaqueClientCredentialsTokenTester.Token
{

    public sealed record TokenPayload
    {
        [JsonPropertyName("id")] public required string Id { get; init; }
        [JsonPropertyName("iss")] public required string Iss { get; init; }
        [JsonPropertyName("sub")] public required string Sub { get; init; }
        [JsonPropertyName("aud")] public required string Aud { get; init; }
        [JsonPropertyName("scope")] public required string[] Scope { get; init; }
        [JsonPropertyName("iat")] public long Iat { get; init; }
        [JsonPropertyName("exp")] public long Exp { get; init; }
    }
    /*
     using System.Security.Cryptography;
       using System.Text;
       
       static string B64(byte[] b) => Convert.ToBase64String(b);
       
       var aesKey = RandomNumberGenerator.GetBytes(32);
       Console.WriteLine("AES-256 Key (base64):");
       Console.WriteLine(B64(aesKey));
       Console.WriteLine();
       
       var clientSecretRaw = RandomNumberGenerator.GetBytes(32);
       var clientSecret = Convert.ToBase64String(clientSecretRaw); // give this string to client
       
       var secretHash = SHA256.HashData(Encoding.UTF8.GetBytes(clientSecret));
       Console.WriteLine("Give to client (client_secret):");
       Console.WriteLine(clientSecret);
       Console.WriteLine();
       Console.WriteLine("Store on server (SecretHash = base64(SHA256(secretUtf8))):");
       Console.WriteLine(B64(secretHash));
     
     

curl -X POST https://your-server/token \
       -H "Authorization: Basic $(printf 'system-xyz:CLIENT_SECRET_HERE' | base64)" \
       -H "Content-Type: application/x-www-form-urlencoded" \
       --data "grant_type=client_credentials&scope=orders.read"


curl https://your-server/protected/orders \
       -H "Authorization: Bearer ACCESS_TOKEN_HERE"





    ------------------------


using System.Security.Cryptography;
       using System.Text;
       
       static string B64(byte[] b) => Convert.ToBase64String(b);
       
       var aesKey = RandomNumberGenerator.GetBytes(32);
       Console.WriteLine("AES-256 key (base64) -> TokenSettings__Keys__key-2026-01:");
       Console.WriteLine(B64(aesKey));
       Console.WriteLine();
       
       var clientSecretRaw = RandomNumberGenerator.GetBytes(32);
       var clientSecret = Convert.ToBase64String(clientSecretRaw);
       
       var hash = SHA256.HashData(Encoding.UTF8.GetBytes(clientSecret));
       
       Console.WriteLine("Give to client (client_secret):");
       Console.WriteLine(clientSecret);
       Console.WriteLine();
       
       Console.WriteLine("Store on server (SecretHash base64):");
       Console.WriteLine(B64(hash));
       Console.WriteLine();
       
       Console.WriteLine("Store on server (SecretHash hex):");
       Console.WriteLine(Convert.ToHexString(hash));
       
     */
}
