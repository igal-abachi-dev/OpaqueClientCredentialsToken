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

        private static (string? id, string? secret) TryParseBasic(string? authHeader) //the industry standard is to rely on HTTPS (TLS)
        {
            if (string.IsNullOrWhiteSpace(authHeader)) return (null, null);
            if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return (null, null);

            var b64 = authHeader["Basic ".Length..].Trim();
            byte[] bytes;
            try { bytes = Convert.FromBase64String(b64); } //client_id:client_secret encoded in Base64.
            catch { return (null, null); }

            var s = Encoding.UTF8.GetString(bytes);
            var idx = s.IndexOf(':');
            if (idx <= 0) return (null, null);

            var id = s[..idx];
            var secret = s[(idx + 1)..];//API Key of client
            return (id, secret);
        }
    }
    /*
     using System.Net.Http.Headers;
       using System.Text;
       
       static async Task<(string AccessToken, int ExpiresIn)> GetTokenAsync(
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
           res.EnsureSuccessStatusCode();
       
           var json = await res.Content.ReadAsStringAsync();
           // deserialize { access_token, token_type, expires_in }
           // (use System.Text.Json)
           throw new NotImplementedException();
       }
       
     
     */
}
/*
 using System.Net;
   using System.Text;
   using Microsoft.Extensions.Primitives;
   
   namespace OpaqueClientCredentialsTokenTester.Token;
   
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
           if (!HttpMethods.IsPost(ctx.Request.Method))
           {
               return new(false, StatusCodes.Status405MethodNotAllowed,
                   "invalid_request", "Token endpoint only supports POST.",
                   null, null, null, null);
           }
   
           // OAuth2 token endpoint requests are form-encoded
           if (!ctx.Request.HasFormContentType)
           {
               return new(false, StatusCodes.Status400BadRequest,
                   "invalid_request", "Content-Type must be application/x-www-form-urlencoded.",
                   null, null, null, null);
           }
   
           // 1) Prefer client_secret_basic
           (string? id, string? secret) = TryParseBasic(ctx.Request.Headers.Authorization);
   
           // 2) Read form (grant_type/scope are in the body)
           var form = await ctx.Request.ReadFormAsync();
           var grantType = ReadFirst(form, "grant_type");
           var scope = ReadFirst(form, "scope");
   
           // 3) Fallback: client_secret_post (allowed, but less preferred)
           id ??= ReadFirst(form, "client_id");
           secret ??= ReadFirst(form, "client_secret");
   
           if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(secret))
           {
               return new(false, StatusCodes.Status401Unauthorized,
                   "invalid_client", "Missing client credentials.",
                   null, null, null, null);
           }
   
           if (string.IsNullOrWhiteSpace(grantType))
           {
               return new(false, StatusCodes.Status400BadRequest,
                   "invalid_request", "Missing grant_type.",
                   null, null, null, null);
           }
   
           return new(true, StatusCodes.Status200OK, null, null, id, secret, grantType, scope);
       }
   
       private static string? ReadFirst(IFormCollection form, string key)
           => form.TryGetValue(key, out StringValues v) ? v.ToString() : null;
   
       private static (string? id, string? secret) TryParseBasic(string? authHeader)
       {
           if (string.IsNullOrWhiteSpace(authHeader)) return (null, null);
           if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return (null, null);
   
           var b64 = authHeader["Basic ".Length..].Trim();
   
           byte[] bytes;
           try { bytes = Convert.FromBase64String(b64); }
           catch { return (null, null); }
   
           var decoded = Encoding.UTF8.GetString(bytes);
           var idx = decoded.IndexOf(':');
           if (idx <= 0) return (null, null);
   
           // Some specs percent-encode these; decoding is harmless if they're “simple”
           var idEnc = decoded[..idx];
           var secretEnc = decoded[(idx + 1)..];
   
           var id = WebUtility.UrlDecode(idEnc);
           var secret = WebUtility.UrlDecode(secretEnc);
           return (id, secret);
       }
   }
   
 
 
 */




////////////////////////////

/*
 using System.Net.Http.Headers;
   using System.Text;
   using Microsoft.Extensions.Primitives;
   
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
               // OAuth2 token requests are form-encoded (application/x-www-form-urlencoded)
               if (!IsFormUrlEncoded(ctx.Request.ContentType))
               {
                   return Fail(400, "invalid_request",
                       "Content-Type must be application/x-www-form-urlencoded");
               }
   
               var form = await ctx.Request.ReadFormAsync();
   
               // "What do you want?"
               var grantType = GetFirst(form, "grant_type");
               var scope = GetFirst(form, "scope");
   
               if (string.IsNullOrWhiteSpace(grantType))
               {
                   return Fail(400, "invalid_request", "Missing grant_type");
               }
   
               // "Who are you?" (client auth) - prefer Basic, fallback to body
               var (basicId, basicSecret, basicOk) = TryParseBasic(ctx.Request.Headers.Authorization);
   
               var bodyId = GetFirst(form, "client_id");
               var bodySecret = GetFirst(form, "client_secret");
   
               string? clientId;
               string? clientSecret;
   
               if (basicOk)
               {
                   // RFC 6749: MUST NOT use more than one client auth method per request.
                   // So if Basic is used, do not accept client_secret in the body.
                   if (!string.IsNullOrEmpty(bodySecret))
                   {
                       return Fail(400, "invalid_request",
                           "Do not send client_secret in the request body when using Authorization: Basic");
                   }
   
                   // Some clients might redundantly include client_id; if present, ensure it matches.
                   if (!string.IsNullOrEmpty(bodyId) && !string.Equals(bodyId, basicId, StringComparison.Ordinal))
                   {
                       return Fail(400, "invalid_request",
                           "client_id in body must match client_id in Authorization header");
                   }
   
                   clientId = basicId;
                   clientSecret = basicSecret;
               }
               else
               {
                   // Fallback: client_secret_post (allowed, but not recommended)
                   clientId = bodyId;
                   clientSecret = bodySecret;
               }
   
               if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
               {
                   // OAuth style: invalid client authentication
                   return Fail(401, "invalid_client", "Missing client credentials");
               }
   
               return new ParsedTokenRequest(
                   Ok: true,
                   StatusCode: 200,
                   Error: null,
                   ErrorDescription: null,
                   ClientId: clientId,
                   ClientSecret: clientSecret,
                   GrantType: grantType,
                   Scope: scope
               );
           }
   
           private static ParsedTokenRequest Fail(int code, string error, string desc)
               => new(false, code, error, desc, null, null, null, null);
   
           private static string? GetFirst(IFormCollection form, string key)
               => form.TryGetValue(key, out StringValues v) ? v.ToString() : null;
   
           private static bool IsFormUrlEncoded(string? contentType)
           {
               if (string.IsNullOrWhiteSpace(contentType)) return false;
               if (!MediaTypeHeaderValue.TryParse(contentType, out var mt)) return false;
               return mt.MediaType.Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase);
           }
   
           private static (string? id, string? secret, bool ok) TryParseBasic(string? authHeader)
           {
               if (string.IsNullOrWhiteSpace(authHeader)) return (null, null, false);
               if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return (null, null, false);
   
               var b64 = authHeader["Basic ".Length..].Trim();
   
               byte[] bytes;
               try { bytes = Convert.FromBase64String(b64); }
               catch { return (null, null, false); }
   
               // Most implementations use ASCII here.
               var s = Encoding.ASCII.GetString(bytes);
   
               var idx = s.IndexOf(':');
               if (idx <= 0) return (null, null, false);
   
               var id = s[..idx];
               var secret = s[(idx + 1)..];
   
               return (id, secret, true);
           }
       }
   }
   
 
 */