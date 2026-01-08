namespace OpaqueClientCredentialsTokenTester.Settings
{
    public sealed class TokenSettings
    {
        public string Issuer { get; set; } = "your-system";
        public string Audience { get; set; } = "your-api-v1";
        public int TokenLifetimeMinutes { get; set; } = 15;

        public string CurrentKeyId { get; set; } = "";
        public Dictionary<string, string> Keys { get; set; } = new();
    }
}
