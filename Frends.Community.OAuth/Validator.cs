using System;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Frends.Community.OAuth.Models;
using Newtonsoft.Json;


[assembly: InternalsVisibleTo("Frends.Community.OAuth.Tests")]
namespace Frends.Community.OAuth
{
    public class Validator
    {
        private static readonly ConcurrentDictionary<string, IConfigurationManager<OpenIdConnectConfiguration>> ConfigurationManagerCache = new ConcurrentDictionary<string, IConfigurationManager<OpenIdConnectConfiguration>>();
        private static readonly SemaphoreSlim InitLock = new SemaphoreSlim(1, 1);
        private static async Task<OpenIdConnectConfiguration> GetConfiguration(ValidateInput input, CancellationToken cancellationToken)
        {
            if (input.ConfigurationSource == ConfigurationSource.Static)
            {
                var configuration =  new OpenIdConnectConfiguration()
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
        public static async Task<ParseResult> ParseToken([PropertyTab]ValidateInput input, [PropertyTab]ParseOptions options, CancellationToken cancellationToken)
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
    }
}
