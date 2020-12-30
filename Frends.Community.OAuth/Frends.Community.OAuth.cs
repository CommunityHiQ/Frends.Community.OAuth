using System;
using System.ComponentModel;
using System.Threading;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Frends.Community.OAuth.Models;
using Microsoft.CSharp;
using Newtonsoft.Json;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

#pragma warning disable 1591

namespace Frends.Community.OAuth
{
    public static class OAuth
    {
        /// <summary>
        /// Validates the provided OAuth JWT token or Authorization header. Documentation: https://github.com/CommunityHiQ/Frends.Community.OAuth/
        /// </summary>
        /// <param name="input">Parameters for the token validation</param>
        /// <returns>string</returns>
        public static async Task<ParseResult> Validate(ValidateInput input, CancellationToken cancellationToken)
        {
            return await ParseToken(input, new ParseOptions
            {
                SkipIssuerValidation = false,
                SkipAudienceValidation = false,
                SkipLifetimeValidation = false
            }, cancellationToken);
        }

        /// <summary>
        /// Parses the provided OAuth JWT token or Authorization header with the option of skipping validations Documentation: https://github.com/CommunityHiQ/Frends.Community.OAuth/
        /// </summary>
        /// <param name="input">Parameters for the token parsing.</param>
        /// <param name="options">Options to skip different validations in the token parsing. </param>
        /// <returns>Object {ClaimsPrincipal ClaimsPrincipal, SecurityToken Token} </returns>
        public static async Task<ParseResult> ParseToken([PropertyTab] ValidateInput input, [PropertyTab] ParseOptions options, CancellationToken cancellationToken)
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
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var user = handler.ValidateToken(input.GetToken(), validationParameters, out var validatedToken);

            return new ParseResult
            {
                ClaimsPrincipal = user,
                Token = validatedToken,
            };
        }

        /// <summary>
        /// Parses a string into an instance of JwtSecurityToken.
        /// 
        /// If the 'jwtToken' is in JWE Compact Serialization format, only the protected header will be deserialized. Use ParseToken() to obtain the payload.
        /// 
        /// JwtSecurityToken see: https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.jwt.jwtsecuritytoken?view=azure-dotnet
        /// </summary>
        /// <param name="input">Parameters for the token parsing.</param>
        /// <returns>JwtSecurityToken</returns>
        public static dynamic ReadToken([PropertyTab] ReadTokenInput input)
        {
            if (input == null)
            {
                return null;
            }
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            return handler.ReadJwtToken(input.JWTToken);
        }

        private static readonly ConcurrentDictionary<string, IConfigurationManager<OpenIdConnectConfiguration>> ConfigurationManagerCache = new ConcurrentDictionary<string, IConfigurationManager<OpenIdConnectConfiguration>>();
        private static readonly SemaphoreSlim InitLock = new SemaphoreSlim(1, 1);
        private static async Task<OpenIdConnectConfiguration> GetConfiguration(ValidateInput input, CancellationToken cancellationToken)
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

            if (!ConfigurationManagerCache.TryGetValue(input.Issuer, out var configurationManager))
            {
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
            }

            return await configurationManager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
        }







































        /// <summary>
        /// This is task
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.OAuth
        /// </summary>
        /// <param name="input">What to repeat.</param>
        /// <param name="options">Define if repeated multiple times. </param>
        /// <param name="cancellationToken"></param>
        /// <returns>{string Replication} </returns>
        public static Result ExecuteOAuth(Parameters input, [PropertyTab] Options options, CancellationToken cancellationToken)
        {
            var repeats = new string[options.Amount];

            for (var i = 0; i < options.Amount; i++)
            {
                // It is good to check the cancellation token somewhere you spend lot of time, e.g. in loops.
                cancellationToken.ThrowIfCancellationRequested();

                repeats[i] = input.Message;
            }

            var output = new Result
            {
                Replication = string.Join(options.Delimiter, repeats)
            };

            return output;
        }
    }
}
