using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Client
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = true;
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
            
            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "cookie";
                    options.DefaultChallengeScheme = "oidc";
                })
                .AddCookie("cookie")
                .AddOpenIdConnect("oidc", options =>
                {
                    options.Authority = "http://localhost:5000";
                    options.ClientId = "mvc";
                    options.ClientSecret = "49C1A7E1-0C79-4A89-A3D6-A37998FB86B0";
                    options.ResponseType = "id_token code";

                    options.SignInScheme = "cookie";
                    options.RequireHttpsMetadata = false;

                    // Allows automatic decryption of JWE identity tokens
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        TokenDecryptionKey = new X509SecurityKey(new X509Certificate2("idsrv3test.pfx", "idsrv3test"))
                    };

                    // Allows JWEs to be validated (work-around for https://github.com/aspnet/AspNetCore/issues/9154)
                    options.ProtocolValidator = new JweProtocolValidator
                    {
                        RequireStateValidation = options.ProtocolValidator.RequireStateValidation,
                        NonceLifetime = options.ProtocolValidator.NonceLifetime
                    };

                    /*options.Events = new OpenIdConnectEvents
                    {
                        // after initial validation, but before calling ProtocolValidator
                        OnTokenValidated = context =>
                        {
                            context.SecurityToken = context.SecurityToken.InnerToken;
                            return Task.CompletedTask;
                        }

                        // https://github.com/aspnet/AspNetCore/issues/9154
                        // no event to handle JWE identity tokens from BOTH authorization endpoint and then token endpoint...

                    };*/
                });
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();

            app.UseAuthentication();

            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }
    }

    public class JweProtocolValidator : OpenIdConnectProtocolValidator
    {
        protected override void ValidateIdToken(OpenIdConnectProtocolValidationContext validationContext)
        {
            if (validationContext.ValidatedIdToken.InnerToken != null)
                validationContext.ValidatedIdToken = validationContext.ValidatedIdToken.InnerToken;

            base.ValidateIdToken(validationContext);
        }

        public override void ValidateTokenResponse(OpenIdConnectProtocolValidationContext validationContext)
        {
            if (validationContext.ValidatedIdToken.InnerToken != null)
                validationContext.ValidatedIdToken = validationContext.ValidatedIdToken.InnerToken;

            base.ValidateTokenResponse(validationContext);
        }

        public override void ValidateUserInfoResponse(OpenIdConnectProtocolValidationContext validationContext)
        {
            if (validationContext.ValidatedIdToken.InnerToken != null)
                validationContext.ValidatedIdToken = validationContext.ValidatedIdToken.InnerToken;

            base.ValidateUserInfoResponse(validationContext);
        }
    }
}
