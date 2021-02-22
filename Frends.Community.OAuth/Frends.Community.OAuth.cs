using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using PemUtils;
using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

#pragma warning disable 1591

namespace Frends.Community.OAuth
{
    public class OAuthTasks
    {
        private static readonly ConcurrentDictionary<string, IConfigurationManager<OpenIdConnectConfiguration>> ConfigurationManagerCache = new ConcurrentDictionary<string, IConfigurationManager<OpenIdConnectConfiguration>>();
        private static readonly SemaphoreSlim InitLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Create a JWT token with specified parameters. 
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.OAuth#CreateToken
        /// </summary>
        /// <param name="parameters">Parameters for the token creation</param>
        /// <returns>string</returns>
        public static string CreateJwtToken(CreateJwtTokenInput parameters)
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

        /// <summary>
        /// Parses the provided OAuth JWT token or Authorization header with the option of skipping validations 
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.OAuth#ParseToken
        /// </summary>
        /// <param name="input">Parameters for the token parsing.</param>
        /// <param name="options">Options to skip different validations in the token parsing. </param>
        /// <param name="cancellationToken">The cancellation token for the task.</param>
        /// <returns>Object {ClaimsPrincipal ClaimsPrincipal, SecurityToken Token} </returns>
        public static async Task<ParseResult> ParseToken([PropertyTab] ValidateParseInput input, [PropertyTab] ParseOptions options, CancellationToken cancellationToken)
        {
            var config = await GetConfiguration(input, cancellationToken).ConfigureAwait(false);

            TokenValidationParameters validationParameters =
                new TokenValidationParameters
                {
                    ValidIssuer = input.Issuer,
                    ValidAudiences = new[] { input.Audience },
                    IssuerSigningKeys = config.SigningKeys,
                    ValidateLifetime = !options.SkipLifetimeValidation,
                    ValidateAudience = !options.SkipAudienceValidation,
                    ValidateIssuer = !options.SkipIssuerValidation
                };
            var handler = new JwtSecurityTokenHandler();
            var user = handler.ValidateToken(input.GetToken(), validationParameters, out var validatedToken);

            return new ParseResult
            {
                ClaimsPrincipal = user,
                Token = validatedToken,
            };
        }

        /// <summary>
        /// Parses a string into an instance of JwtSecurityToken.
        /// If the 'jwtToken' is in JWE Compact Serialization format, only the protected header will be deserialized. Use ParseToken to obtain the payload.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.OAuth#ReadJwtToken
        /// JwtSecurityToken see: https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.jwt.jwtsecuritytoken?view=azure-dotnet
        /// </summary>
        /// <param name="input">Parameters for the token parsing.</param>
        /// <returns>JwtSecurityToken</returns>
        public static dynamic ReadJwtToken([PropertyTab] ReadTokenInput input)
        {
            if (input == null)
            {
                return null;
            }
            var handler = new JwtSecurityTokenHandler();
            return handler.ReadJwtToken(input.JwtToken);
        }

        /// <summary>
        /// Validates the provided OAuth JWT token or Authorization header. 
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.OAuth#ValidateToken
        /// </summary>
        /// <param name="input">Parameters for the token validation</param>
        /// <param name="cancellationToken">The cancellation token for the task.</param>
        /// <returns>string</returns>
        public static async Task<ParseResult> ValidateToken(ValidateParseInput input, CancellationToken cancellationToken)
        {
            return await ParseToken(input, new ParseOptions
            {
                SkipIssuerValidation = false,
                SkipAudienceValidation = false,
                SkipLifetimeValidation = false
            }, cancellationToken);
        }

        /// <summary>
        /// An internal method to get the configuration.
        /// </summary>
        /// <param name="input">Input params for the task.</param>
        /// <param name="cancellationToken">The cancellation token for the task.</param>
        private static async Task<OpenIdConnectConfiguration> GetConfiguration(ValidateParseInput input, CancellationToken cancellationToken)
        {
            if (input.ConfigurationSource == ConfigurationSource.Static)
            {
                var configuration = new OpenIdConnectConfiguration()
                {
                    JsonWebKeySet = JsonConvert.DeserializeObject<JsonWebKeySet>(input.StaticJwksConfiguration)
                };
                foreach (SecurityKey key in configuration.JsonWebKeySet.GetSigningKeys())
                {
                    configuration.SigningKeys.Add(key);
                }

                return configuration;
            }

            if (ConfigurationManagerCache.TryGetValue(input.Issuer, out var configurationManager))
                return await configurationManager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
            await InitLock.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);
            try
            {
                configurationManager = ConfigurationManagerCache.GetOrAdd(input.Issuer, issuer =>
                    new ConfigurationManager<OpenIdConnectConfiguration>(
                        input.WellKnownConfigurationUrl,
                        new OpenIdConnectConfigurationRetriever()
                    ));
            }
            finally
            {
                InitLock.Release();
            }

            return await configurationManager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
