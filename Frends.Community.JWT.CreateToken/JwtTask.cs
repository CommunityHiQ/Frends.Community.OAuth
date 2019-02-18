using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using PemUtils;

namespace Frends.Community.JWT
{
    public class JwtTask
    {
        /// <summary>
        /// Create a JWT token with specified parameters. Documentation: https://github.com/CommunityHiQ/Frends.Community.JWT.CreateToken
        /// </summary>
        /// <param name="parameters">Parameters for the token creation</param>
        /// <returns>string</returns>
        public static string CreateJwtToken(CreateJwtTokenParameters parameters)
        {
            var handler = new JwtSecurityTokenHandler();
            
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(parameters.PrivateKey)))
            using (var reader = new PemReader(stream))
            {
                var rsaParameters = reader.ReadRsaKey();
                var key = new RsaSecurityKey(rsaParameters);
                var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

                var claims = new ClaimsIdentity();
                if (parameters.Claims != null)
                {
                    foreach (var claim in parameters.Claims)
                    {
                        claims.AddClaim(new Claim(claim.ClaimKey, claim.ClaimValue));
                    }
                }

                // Create JWT
                var token = handler.CreateJwtSecurityToken(new SecurityTokenDescriptor
                {
                    Issuer = parameters.Issuer,
                    Audience = parameters.Audience,
                    Expires = parameters.Expires,
                    NotBefore = parameters.NotBefore,
                    Subject = claims,
                    SigningCredentials = signingCredentials,
                });

                return handler.WriteToken(token);
            }
        }
    }
}
