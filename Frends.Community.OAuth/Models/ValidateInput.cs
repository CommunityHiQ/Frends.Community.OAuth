using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.Community.OAuth.Models
{
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
}