using System.Text;
using System.Text.Json;

namespace OpaqueClientCredentialsTokenTester.Token
{
    public sealed record ParsedTokenRequest(
        bool Ok,
        int StatusCode,
        string? Error,
        string? ErrorDescription,
        string? ClientId,
        string? ClientSecret,
        string? GrantType,
        string? Scope);

    public static class TokenRequestParser
    {
        public static async Task<ParsedTokenRequest> ParseAsync(HttpContext ctx)
        {
            // 1) Client credentials: prefer Basic Auth
            (string? id, string? secret) = TryParseBasic(ctx.Request.Headers.Authorization);

            string? grantType = null;
            string? scope = null;

            // 2) Read body: form or JSON
            if (ctx.Request.HasFormContentType)
            {
                var form = await ctx.Request.ReadFormAsync();
                grantType = form["grant_type"];
                scope = form["scope"];

                // If no basic auth, allow credentials in form (less ideal but common)
                id ??= form["client_id"];
                secret ??= form["client_secret"];
            }
            else
            {
                // If JSON, accept { client_id/client_secret/grant_type/scope }
                try
                {
                    var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
                    var root = doc.RootElement;

                    grantType = root.TryGetProperty("grant_type", out var gt) ? gt.GetString() : grantType;
                    scope = root.TryGetProperty("scope", out var sc) ? sc.GetString() : scope;

                    id ??= root.TryGetProperty("client_id", out var cid) ? cid.GetString() : null;
                    secret ??= root.TryGetProperty("client_secret", out var cs) ? cs.GetString() : null;
                }
                catch
                {
                    // ignore if no JSON body
                }
            }

            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(secret))
                return new(false, 401, "invalid_client", "Missing client credentials", null, null, null, null);

            if (string.IsNullOrWhiteSpace(grantType))
                return new(false, 400, "invalid_request", "Missing grant_type", null, null, null, null);

            return new(true, 200, null, null, id, secret, grantType, scope);
        }

        private static (string? id, string? secret) TryParseBasic(string? authHeader)
        {
            if (string.IsNullOrWhiteSpace(authHeader)) return (null, null);
            if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return (null, null);

            var b64 = authHeader["Basic ".Length..].Trim();
            byte[] bytes;
            try { bytes = Convert.FromBase64String(b64); }
            catch { return (null, null); }

            var s = Encoding.UTF8.GetString(bytes);
            var idx = s.IndexOf(':');
            if (idx <= 0) return (null, null);

            var id = s[..idx];
            var secret = s[(idx + 1)..];
            return (id, secret);
        }
    }

}
