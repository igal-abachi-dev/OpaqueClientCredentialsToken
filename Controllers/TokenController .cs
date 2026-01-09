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
       return System.Text.Json.JsonSerializer.Deserialize<TokenResponse>(json)!; //Storage: In-Memory Cache (RAM).

   //Check Cache -> Found? Return Token.
   //Not Found? Call GetTokenAsync.
   //Save to Cache with TimeSpan.FromSeconds(response.expires_in - 60). (Subtract 60 seconds as a safety buffer).

   }
   
   public sealed record TokenResponse(string access_token, string token_type, int expires_in);
   
 
 

using Microsoft.Extensions.Caching.Memory;
   using System.Net.Http.Headers;
   
   public class TokenService
   {
       private readonly IMemoryCache _cache;
       private readonly HttpClient _http;
       
       // 1. The Semaphore: Allows only 1 thread to request a token at a time
       private static readonly SemaphoreSlim _lock = new SemaphoreSlim(1, 1);
       private const string CacheKey = "api_access_token";
   
       public TokenService(IMemoryCache cache, HttpClient http)
       {
           _cache = cache;
           _http = http;
       }
   
       public async Task<string> GetTokenAsync()
       {
           // 1. Fast Path: Check Cache
           if (_cache.TryGetValue(CacheKey, out string? token))
           {
               return token!;
           }
   
           // 2. Slow Path: Token missing/expired. Wait for the lock.
           await _lock.WaitAsync();
           try
           {
               // 3. Double-Check! (Crucial)
               // Someone might have refreshed the token while we were waiting in line.
               if (_cache.TryGetValue(CacheKey, out token))
               {
                   return token!;
               }
   
               // 4. Actually call the API (Only one thread reaches here)
               // (Insert your specific GetTokenAsync logic here or call a helper)
               var response = await CallYourTokenEndpointRaw(); 
   
               // 5. Save to Cache
               // Subtract 60 seconds so we stop using it before it actually dies
               var expiry = TimeSpan.FromSeconds(response.expires_in - 60);
               
               _cache.Set(CacheKey, response.access_token, expiry);
   
               return response.access_token;
           }
           finally
           {
               // 6. Always release the lock!
               _lock.Release();
           }
       }
   }


Fix 1: Cache key must include scope (and optionally audience)

If they call your API with different scopes, a single global api_access_token cache key is wrong.

Fix 2: Don’t do expires_in - 60 if it can go <= 0

If token lifetime is 30s (or misconfigured), TimeSpan.FromSeconds(expires_in - 60) breaks.

Fix 3: Cache absolute expiration, not just TTL guesswork

Use AbsoluteExpirationRelativeToNow.

Fix 4: Validate token_type == "Bearer"

Defensive check.


1) In-memory cache (per process)  default recommendation

What they do: keep access_token + expires_at in RAM only; refresh ~60s before expiry.
Why: simplest + safest (no disk). This is also the typical pattern recommended for machine-to-machine scenarios (see MSAL guidance).
When: single instance, or “it’s ok if restart triggers a new /token call”.

2) In-memory cache + concurrency guard (avoid stampede) 

Same as #1, but ensure only one thread refreshes at a time (SemaphoreSlim/lock).
Why: prevents 50 parallel requests all calling /token at once.
 

How they should use it on API calls (the “correct” wire pattern)
On each call to your API:

Use the bearer token in the Authorization header (don’t put it in query string).
Query-string tokens are specifically risky because they leak into logs/referrers/etc.

req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

Use #1 (in-memory cache) + concurrency guard

Refresh at expires_at - 60s

If you get 401: refresh and retry once

Never log Authorization headers or token bodies (scrub/redact)

 */




/*
 using System.Net.Http.Headers;
   using System.Text;
   using System.Text.Json;
   using Microsoft.Extensions.Caching.Memory;
   
   public sealed record TokenResponse(string access_token, string token_type, int expires_in);
   
   public sealed class ClientCredentialsTokenProvider
   {
       private readonly IMemoryCache _cache;
       private readonly HttpClient _http;
       private readonly Uri _tokenEndpoint;
       private readonly string _clientId;
       private readonly string _clientSecret;
   
       // per-scope locks are better than a single global lock
       private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, SemaphoreSlim> _locks = new();
   
       public ClientCredentialsTokenProvider(
           IMemoryCache cache,
           HttpClient http,
           Uri tokenEndpoint,
           string clientId,
           string clientSecret)
       {
           _cache = cache;
           _http = http;
           _tokenEndpoint = tokenEndpoint;
           _clientId = clientId;
           _clientSecret = clientSecret;
       }
   
       public async Task<string> GetAccessTokenAsync(string scope, CancellationToken ct = default)
       {
           var cacheKey = $"api_access_token::{scope}";
           if (_cache.TryGetValue(cacheKey, out string? token) && !string.IsNullOrWhiteSpace(token))
               return token!;
   
           var sem = _locks.GetOrAdd(cacheKey, _ => new SemaphoreSlim(1, 1));
           await sem.WaitAsync(ct);
           try
           {
               // double-check after acquiring lock
               if (_cache.TryGetValue(cacheKey, out token) && !string.IsNullOrWhiteSpace(token))
                   return token!;
   
               var resp = await RequestTokenAsync(scope, ct);
   
               if (!resp.token_type.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
                   throw new InvalidOperationException($"Unexpected token_type '{resp.token_type}'");
   
               // safety buffer: 60s or 10% of lifetime, whichever is smaller, but never negative
               var buffer = Math.Min(60, Math.Max(1, resp.expires_in / 10));
               var ttlSeconds = Math.Max(1, resp.expires_in - buffer);
   
               _cache.Set(
                   cacheKey,
                   resp.access_token,
                   new MemoryCacheEntryOptions
                   {
                       AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(ttlSeconds)
                   });
   
               return resp.access_token;
           }
           finally
           {
               sem.Release();
           }
       }
   
       private async Task<TokenResponse> RequestTokenAsync(string scope, CancellationToken ct)
       {
           var basic = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_clientId}:{_clientSecret}"));
   
           using var req = new HttpRequestMessage(HttpMethod.Post, _tokenEndpoint);
           req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
   
           // OAuth2 token request params go in x-www-form-urlencoded body (grant_type/scope)
           req.Content = new FormUrlEncodedContent(new[]
           {
               new KeyValuePair<string,string>("grant_type", "client_credentials"),
               new KeyValuePair<string,string>("scope", scope),
           });
   
           using var res = await _http.SendAsync(req, ct);
           var json = await res.Content.ReadAsStringAsync(ct);
   
           if (!res.IsSuccessStatusCode)
               throw new InvalidOperationException($"Token endpoint failed: {(int)res.StatusCode} {json}");
   
           var tr = JsonSerializer.Deserialize<TokenResponse>(json)
                    ?? throw new InvalidOperationException("Token endpoint returned invalid JSON.");
   
           if (string.IsNullOrWhiteSpace(tr.access_token) || tr.expires_in <= 0)
               throw new InvalidOperationException("Token endpoint returned invalid token payload.");
   
           return tr;
       }
   }
   

public sealed class BearerTokenHandler : DelegatingHandler
   {
       private readonly ClientCredentialsTokenProvider _tokens;
       private readonly string _scope;
   
       public BearerTokenHandler(ClientCredentialsTokenProvider tokens, string scope)
       {
           _tokens = tokens;
           _scope = scope;
       }
   
       protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
       {
           var token = await _tokens.GetAccessTokenAsync(_scope, ct);
           request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
   
           var res = await base.SendAsync(request, ct);
   
           // Optional: if 401, refresh once and retry once
           if (res.StatusCode == System.Net.HttpStatusCode.Unauthorized)
           {
               res.Dispose();
               // force refresh by evicting cache key if you implement that, or add a ForceRefresh path
               token = await _tokens.GetAccessTokenAsync(_scope, ct);
               request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
               return await base.SendAsync(request, ct);
           }
   
           return res;
       }
   }
   
 


program:
   builder.Services.AddMemoryCache();
   builder.Services.AddHttpClient<ClientCredentialsTokenProvider>(client => 
   {
       // You can set default timeouts here if you want
       client.Timeout = TimeSpan.FromSeconds(10); 
   });
   
   // Register as Singleton (Important!)
   builder.Services.AddSingleton<ClientCredentialsTokenProvider>(sp => 
   {
       var cache = sp.GetRequiredService<IMemoryCache>();
       var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(ClientCredentialsTokenProvider));
       
       return new ClientCredentialsTokenProvider(
           cache, 
           http, 
           new Uri("https://api.yoursite.com/Token"), 
           "your_client_id", 
           "your_base64_secret" // Passed via config/environment usually
       );
   });
 */