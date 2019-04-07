using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer
{
    public class JweTokenCreationService : DefaultTokenCreationService
    {
        public JweTokenCreationService(
            ISystemClock clock, 
            IKeyMaterialService keys, 
            ILogger<DefaultTokenCreationService> logger) 
            : base(clock, keys, logger)
        {
        }

        public override async Task<string> CreateTokenAsync(Token token)
        {
            if (token.Type == IdentityServerConstants.TokenTypes.IdentityToken)
            {
                var payload = await base.CreatePayloadAsync(token);

                var signingCredentials = await Keys.GetSigningCredentialsAsync();
                X509SigningCredentials test = null;
                if (signingCredentials is X509SigningCredentials) test = signingCredentials as X509SigningCredentials;

                var handler = new JsonWebTokenHandler();
                var jwe = handler.CreateToken(
                    payload.SerializeToJson(),
                    test ?? signingCredentials,
                    new X509EncryptingCredentials(new X509Certificate2("idsrv3test.cer"))); // hardcoded, instead load public key per client

                return jwe;
            }

            return await base.CreateTokenAsync(token);
        }
    }
}