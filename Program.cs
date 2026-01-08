
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using OpaqueClientCredentialsTokenTester.Settings;
using OpaqueClientCredentialsTokenTester.Token;

namespace OpaqueClientCredentialsTokenTester
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.Configure<TokenSettings>(builder.Configuration.GetSection("TokenSettings"));
            builder.Services.Configure<ClientsOptions>(builder.Configuration.GetSection("Clients"));


            builder.Services.AddSingleton<KeyManager>();
            builder.Services.AddSingleton<ClientStore>();
            builder.Services.AddSingleton<OpaqueTokenService>();
            // Add services to the container


            builder.Services
                .AddAuthentication("OpaqueBearer")
                .AddScheme<AuthenticationSchemeOptions, OpaqueBearerHandler>("OpaqueBearer", _ => { });

            builder.Services.AddAuthorization(options =>
            {
                // Example:
                //options.AddPolicy("orders.read", p => p.RequireAuthenticatedUser().RequireScope("orders.read"));
                //options.AddPolicy("orders.write", p => p.RequireAuthenticatedUser().RequireScope("orders.write"));
            });
            builder.Services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();

            builder.Services.AddControllers();
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddOpenApi();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
