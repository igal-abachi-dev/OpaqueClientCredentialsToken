namespace OpaqueClientCredentialsTokenTester.Token;

using Microsoft.AspNetCore.Authorization;

public static class ScopePolicyExtensions
{
    public static AuthorizationPolicyBuilder RequireScope(this AuthorizationPolicyBuilder builder, string scope)
        => builder.AddRequirements(new ScopeRequirement(scope));
}

public sealed record ScopeRequirement(string Scope) : IAuthorizationRequirement;

public sealed class ScopeAuthorizationHandler : AuthorizationHandler<ScopeRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeRequirement requirement)
    {
        var has = context.User.FindAll("scope").Any(c => string.Equals(c.Value, requirement.Scope, StringComparison.Ordinal));
        if (has) context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
