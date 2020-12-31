#pragma warning disable 1591

using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace Frends.Community.OAuth
{
    /// <summary>
    /// The enumerator for the configuration source.
    /// </summary>
    public enum ConfigurationSource
    {
        WellKnownConfigurationUrl,
        Static
    }

    /// <summary>
    /// Input parameters for ReadToken task.
    /// </summary>
    public class ReadTokenInput
    {
        /// <summary>
        /// A 'JSON Web Token' (JWT) in JWS or JWE Compact Serialization Format.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("")]
        public string JWTToken { get; set; }
    }

    /// <summary>
    /// Input parameters for Validate task.
    /// </summary>
    public class ValidateInput
    {
        internal string GetToken()
        {
            if (string.IsNullOrEmpty(AuthHeaderOrToken))
            {
                throw new Exception("AuthHeader did not contain a Bearer token");
            }

            if (AuthHeaderOrToken.StartsWith("Bearer ", StringComparison.CurrentCultureIgnoreCase))
            {
                return AuthHeaderOrToken.Substring("Bearer ".Length).Trim();
            }

            return AuthHeaderOrToken;
        }
        /// <summary>
        /// Either the JWT token or the Authorization header value through #trigger.data.httpHeaders["Authorization"]
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        [DefaultValue("#trigger.data.httpHeaders[\"Authorization\"]")]
        public string AuthHeaderOrToken { get; set; }

        /// <summary>
        /// The expected Audiences of the token, e.g. ClientId
        /// </summary>
        [DefaultValue("")]
        [DisplayFormat(DataFormatString = "Text")]
        public string Audience { get; set; }

        /// <summary>
        /// The expected Issuer of the token
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("https://xyz.eu.auth0.com/")]
        public string Issuer { get; set; }

        public ConfigurationSource ConfigurationSource { get; set; }

        /// <summary>
        /// The URL where the .well-known configuration for the issuer is located
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [UIHint(nameof(ConfigurationSource), "", ConfigurationSource.WellKnownConfigurationUrl)]
        [DefaultValue("https://xyz.eu.auth0.com/.well-known/openid-configuration")]
        public string WellKnownConfigurationUrl { get; set; }

        /// <summary>
        /// Static signing keys to use, can be found in the jwks_uri from the .well-known openid-configurations
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [UIHint(nameof(ConfigurationSource), "", ConfigurationSource.Static)]
        public string StaticJwksConfiguration { get; set; }
    }

    /// <summary>
    /// Options for method ParseToken().
    /// </summary>
    public class ParseOptions
    {
        /// <summary>
        /// Should the issuer (iss) validation be skipped
        /// </summary>
        public bool SkipIssuerValidation { get; set; }
        
        /// <summary>
        /// Should audience (aud) validation be skipped
        /// </summary>
        public bool SkipAudienceValidation { get; set; }
        
        /// <summary>
        /// Should lifetime (exp,nbf) validation be skipped 
        /// </summary>
        public bool SkipLifetimeValidation { get; set; }
    }

    /// <summary>
    /// The result object for method ParseToken().
    /// </summary>
    public class ParseResult
    {
        /// <summary>
        /// A claim-based identity.
        /// </summary>
        public ClaimsPrincipal ClaimsPrincipal { get; set; }

        /// <summary>
        /// A validated security token.
        /// </summary>
        public SecurityToken Token { get; set; }
    }
}
