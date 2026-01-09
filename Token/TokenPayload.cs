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
       


       This is the standard length for API secrets (AWS Secret Keys are 40 chars, less than 44).
       var clientSecretRaw = RandomNumberGenerator.GetBytes(32); //256 bits of entropy like aes
       var clientSecret = Convert.ToBase64String(clientSecretRaw); // give this 44char api key string to client
       
       var secretHash = SHA256.HashData(Encoding.UTF8.GetBytes(clientSecret));
       Console.WriteLine("Give to client (client_secret):");
       Console.WriteLine(clientSecret);
       Console.WriteLine();
       Console.WriteLine("Store on server (SecretHash = base64(SHA256(secretUtf8))):");
       Console.WriteLine(B64(secretHash));
     
    ///////////////////////////////////////////////////////////////////////
    how to pass it to client securely:
       Step 1: Create a text file (Name it something boring like Config_2024.txt or Data_Update.txt.) containing the Client ID and Secret.
       Step 2: Compress it with 7-Zip
       Crucial: Select Archive format: 7z , and select AES-256 encryption and  Enable "Encrypt Header" for filenames,
       Set a strong random password  16 chars or above (Numbers, Upper, Lower, Symbols)., using generator (openssl rand / KeePassXC) for entropy
       Step 3 (Channel A): Email the .7z file to their  email.
       Step 4 (Channel B): Send the password WhatsApp (e2e signal protocol)
       step 5:Hygiene, after client received and downloaded/opened it , both sides delete the email and whatsapp message (also from deleted messages) , emails jave Journaling backups that deleted after years


    //////////
    //https://1password.com/password-generator  is nice: local is better
    gen password powershell:
       $chars = 33..126 | ForEach-Object { [char]$_ }
       $bytes = New-Object byte[] 24

       $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
       $rng.GetBytes($bytes)
       $rng.GetBytes($bytes)
       $rng.GetBytes($bytes)
       $rng.GetBytes($bytes)
       $rng.GetBytes($bytes)
       $rng.Dispose()
    
       $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Count] })
       Write-Host $password -ForegroundColor Green
     

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
