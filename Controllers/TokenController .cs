using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Runtime;
using OpaqueClientCredentialsTokenTester.Settings;
using OpaqueClientCredentialsTokenTester.Token;

namespace OpaqueClientCredentialsTokenTester.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //[Route("token")] // Maps to /token
    public class TokenController : ControllerBase
    {
        private readonly ClientStore _clients;
        private readonly OpaqueTokenService _tokens;
        private readonly TokenSettings _settings;

        // Constructor Injection
        public TokenController(
            ClientStore clients,
            OpaqueTokenService tokens,
            IOptions<TokenSettings> settingsOpt)
        {
            _clients = clients;
            _tokens = tokens;
            _settings = settingsOpt.Value;
        }

        [HttpPost]
        public async Task<IActionResult> GenerateToken()
        {
            // 'HttpContext' is available as a property in ControllerBase
            var parsed = await TokenRequestParser.ParseAsync(HttpContext);

            if (!parsed.Ok)
            {
                return StatusCode(parsed.StatusCode, new
                {
                    error = parsed.Error,
                    error_description = parsed.ErrorDescription
                });
            }

            if (!string.Equals(parsed.GrantType, "client_credentials", StringComparison.Ordinal))
                return BadRequest(new { error = "unsupported_grant_type" });

            if (!_clients.TryGet(parsed.ClientId!, out var client))
                return Unauthorized(new { error = "invalid_client" });

            if (!_clients.VerifySecret(client, parsed.ClientSecret!))
                return Unauthorized(new { error = "invalid_client" });

            // Scope handling
            var allowed = client.AllowedScopes ?? Array.Empty<string>();
            var requested = (parsed.Scope ?? "")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            string[] finalScopes;
            if (requested.Length == 0)
            {
                finalScopes = allowed;
            }
            else
            {
                var allowedSet = new HashSet<string>(allowed, StringComparer.Ordinal);
                if (requested.Any(s => !allowedSet.Contains(s)))
                    return BadRequest(new { error = "invalid_scope" });

                finalScopes = requested;
            }

            var now = DateTimeOffset.UtcNow;
            var payload = new TokenPayload
            {
                Id = Guid.NewGuid().ToString("N"),
                Iss = _settings.Issuer,
                Sub = parsed.ClientId!,
                Aud = _settings.Audience,
                Scope = finalScopes,
                Iat = now.ToUnixTimeSeconds(), 
                Exp = now.AddMinutes(_settings.TokenLifetimeMinutes).ToUnixTimeSeconds()
            };

            var token = _tokens.Encrypt(payload);

            // OAuth guidance: do not cache token responses
            Response.Headers.CacheControl = "no-store";
            Response.Headers.Pragma = "no-cache";

            return Ok(new
            {
                access_token = token,
                token_type = "Bearer",
                expires_in = _settings.TokenLifetimeMinutes * 60
            });
        }
    }
}
