namespace OpaqueClientCredentialsTokenTester.Settings;

public sealed class ClientConfig
{
    public string SecretHash { get; set; } = ""; // base64(SHA256(secretUtf8))
    public string[] AllowedScopes { get; set; } = Array.Empty<string>();
}