using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpaqueClientCredentialsTokenTester.Settings;
using OpaqueClientCredentialsTokenTester.Token;
using System.Runtime;
using System.Text.Encodings.Web;
using static System.Net.Mime.MediaTypeNames;

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
            //SRPv6 / Pake: adds a lot of complexity, and gives you little if you already require TLS + high-entropy secrets. , no need
            //If your goal is “don’t rely on a shared secret,” the industry answer is asymmetric client auth (below), not SRP.
            //Require TLS and keep tokens short-lived (15m is right).
            //Support client_secret_basic(Basic header) +application / x - www - form - urlencoded.
            //
            
            // 'HttpContext' is available as a property in ControllerBase
            var parsed = await TokenRequestParser.ParseAsync(HttpContext);

            /*
             Use application/x-www-form-urlencoded (OAuth2 standard)

OAuth 2.0 defines token endpoint requests as form-encoded parameters (not JSON) and shows grant_type=client_credentials exactly in this format.

 Prefer putting client_id:client_secret in the Authorization header (Basic)

OAuth2 allows the client to authenticate to the token endpoint using HTTP Basic (and it’s the most widely supported/expected for confidential clients).

Request (recommended): client_secret_basic
POST /token HTTP/1.1
Host: api.yourserver.com
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=orders.read%20orders.write


Why this is best in practice

Many gateways/loggers are more likely to scrub Authorization than request bodies.

Keeps “credentials” (auth) separate from “parameters” (grant_type/scope).

You should still assume either headers or bodies can be logged somewhere and configure redaction appropriately—TLS protects in transit, not in logs.
             
             */

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
