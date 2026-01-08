namespace OpaqueClientCredentialsTokenTester.Token
{
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.Extensions.Options;
    using OpaqueClientCredentialsTokenTester.Settings;
    using System.Security.Claims;

    public sealed class OpaqueBearerHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly OpaqueTokenService _tokens;
        private readonly TokenSettings _settings;

        public OpaqueBearerHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            System.Text.Encodings.Web.UrlEncoder encoder,
            ISystemClock clock,
            OpaqueTokenService tokens,
            IOptions<TokenSettings> tokenSettings)
            : base(options, logger, encoder, clock)
        {
            _tokens = tokens;
            _settings = tokenSettings.Value;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var auth = Request.Headers.Authorization.ToString();
            if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(AuthenticateResult.NoResult());

            var token = auth["Bearer ".Length..].Trim();

            if (!_tokens.TryDecrypt(token, out var payload, out var err))
            {
                Context.Items["auth_error"] = "invalid_token";
                Context.Items["auth_error_description"] = err;
                return Task.FromResult(AuthenticateResult.Fail("invalid_token"));
            }

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            const int skewSeconds = 30;

            // exp check
            if (payload!.Exp < now - skewSeconds)
            {
                Context.Items["auth_error"] = "invalid_token";
                Context.Items["auth_error_description"] = "expired";
                return Task.FromResult(AuthenticateResult.Fail("expired"));
            }

            // iat sanity (optional but useful)
            if (payload.Iat > now + skewSeconds)
            {
                Context.Items["auth_error"] = "invalid_token";
                Context.Items["auth_error_description"] = "iat_in_future";
                return Task.FromResult(AuthenticateResult.Fail("iat_in_future"));
            }

            // iss/aud binding (critical)
            if (!string.Equals(payload.Iss, _settings.Issuer, StringComparison.Ordinal))
                return Task.FromResult(AuthenticateResult.Fail("invalid_issuer"));

            if (!string.Equals(payload.Aud, _settings.Audience, StringComparison.Ordinal))
                return Task.FromResult(AuthenticateResult.Fail("invalid_audience"));

            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, payload.Sub),
            new Claim("client_id", payload.Sub),
            new Claim("aud", payload.Aud),
            new Claim("iss", payload.Iss),
            new Claim("id", payload.Id)
        };

            foreach (var s in payload.Scope ?? Array.Empty<string>())
                claims.Add(new Claim("scope", s));

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return Task.FromResult(AuthenticateResult.Success(ticket));
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // RFC 6750 recommends WWW-Authenticate Bearer challenges on 401 :contentReference[oaicite:7]{index=7}
            Response.StatusCode = 401;

            var err = Context.Items.TryGetValue("auth_error", out var e) ? e?.ToString() : "invalid_token";
            var desc = Context.Items.TryGetValue("auth_error_description", out var d) ? d?.ToString() : null;

            var header = desc is null
                ? $"Bearer error=\"{err}\""
                : $"Bearer error=\"{err}\", error_description=\"{desc}\"";

            Response.Headers.WWWAuthenticate = header;
            return Task.CompletedTask;
        }
    }

}
