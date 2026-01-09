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

/*
 using Microsoft.AspNetCore.Mvc;
   using Microsoft.Extensions.Options;
   using OpaqueClientCredentialsTokenTester.Settings;
   using OpaqueClientCredentialsTokenTester.Token;
   
   namespace OpaqueClientCredentialsTokenTester.Controllers;
   
   [ApiController]
   [Route("token")] // <-- canonical OAuth-ish path
   public sealed class TokenController : ControllerBase
   {
       private readonly ClientStore _clients;
       private readonly OpaqueTokenService _tokens;
       private readonly TokenSettings _settings;
   
       public TokenController(ClientStore clients, OpaqueTokenService tokens, IOptions<TokenSettings> settingsOpt)
       {
           _clients = clients;
           _tokens = tokens;
           _settings = settingsOpt.Value;
       }
   
       // Token endpoint is form-encoded in OAuth2
       [HttpPost]
       [Consumes("application/x-www-form-urlencoded")]
       public async Task<IActionResult> GenerateToken()
       {
           var parsed = await TokenRequestParser.ParseAsync(HttpContext);
   
           if (!parsed.Ok)
           {
               // For invalid_client, RFC6749 expects 401 + WWW-Authenticate
               if (parsed.StatusCode == StatusCodes.Status401Unauthorized &&
                   string.Equals(parsed.Error, "invalid_client", StringComparison.Ordinal))
               {
                   Response.Headers["WWW-Authenticate"] = "Basic realm=\"token\", charset=\"UTF-8\"";
               }
   
               return StatusCode(parsed.StatusCode, new
               {
                   error = parsed.Error,
                   error_description = parsed.ErrorDescription
               });
           }
   
           if (!string.Equals(parsed.GrantType, "client_credentials", StringComparison.Ordinal))
               return BadRequest(new { error = "unsupported_grant_type" });
   
           if (!_clients.TryGet(parsed.ClientId!, out var client))
               return InvalidClient();
   
           if (!_clients.VerifySecret(client, parsed.ClientSecret!))
               return InvalidClient();
   
           // Scope handling (your logic is fine)
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
   
           // Required for token responses
           Response.Headers.CacheControl = "no-store";
           Response.Headers.Pragma = "no-cache";
   
           return Ok(new
           {
               access_token = token,
               token_type = "Bearer",
               expires_in = _settings.TokenLifetimeMinutes * 60
           });
       }
   
       private IActionResult InvalidClient()
       {
           Response.Headers["WWW-Authenticate"] = "Basic realm=\"token\", charset=\"UTF-8\"";
           return Unauthorized(new { error = "invalid_client" });
       }
   }
   
 
 */


/*
 POST /token HTTP/1.1
   Host: api.yourserver.com
   Authorization: Basic base64url_or_base64(client_id:client_secret)
   Content-Type: application/x-www-form-urlencoded
   
   grant_type=client_credentials&scope=orders.read%20orders.write
   

curl -X POST "https://api.yourserver.com/token" \
   -H "Authorization: Basic $(printf '%s' 'system-xyz:THE_SECRET' | base64)" \
   -H "Content-Type: application/x-www-form-urlencoded" \
   --data "grant_type=client_credentials&scope=orders.read%20orders.write"


using System.Net.Http.Headers;
   using System.Text;
   
   static async Task<TokenResponse> GetTokenAsync(
       HttpClient http,
       Uri tokenEndpoint,
       string clientId,
       string clientSecret,
       string scope)
   {
       var basic = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}"));
   
       using var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
       req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
       req.Content = new FormUrlEncodedContent(new[]
       {
           new KeyValuePair<string,string>("grant_type", "client_credentials"),
           new KeyValuePair<string,string>("scope", scope),
       });
   
       using var res = await http.SendAsync(req);
       var json = await res.Content.ReadAsStringAsync();
   
       res.EnsureSuccessStatusCode();
       return System.Text.Json.JsonSerializer.Deserialize<TokenResponse>(json)!;
   }
   
   public sealed record TokenResponse(string access_token, string token_type, int expires_in);
   
 
 
 
 */