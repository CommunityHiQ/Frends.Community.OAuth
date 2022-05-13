#pragma warning disable 1591

using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace Frends.Community.OAuth
{
    /// <summary>
    /// Input parameters for CreateJwtToken task.
    /// </summary>
    public class CreateJwtTokenInput
    {
        /// <summary>
        /// Value for "iss" (Issuer) Claim.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("ISSUER")]
        public string Issuer { get; set; }

        /// <summary>
        /// Value for "aud" (Audience) Claim.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("AUDIENCE")]
        public string Audience { get; set; }

        /// <summary>
        /// Value for "exp" (Expiration Time) Claim.
        /// </summary>
        [DefaultValue("DateTime.Now.AddDays(7)")]
        public DateTime? Expires { get; set; }

        /// <summary>
        /// Value for "nbf" (Not Before) Claim.
        /// </summary>
        [DefaultValue("DateTime.Now.AddDays(1)")]
        public DateTime? NotBefore { get; set; }

        /// <summary>
        /// Value for "x5t" (X.509 Certificate SHA-1 Thumbprint) Header
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("X5T")]
        public string X509Thumbprint { get; set; }

        /// <summary>
        /// Private key for signing.
        /// The key should be in PEM format for asymmetric algorithms.
        /// If symmetric algorithms is used, key can be any string.
        /// </summary>
        [PasswordPropertyText]
        public string PrivateKey { get; set; }

        /// <summary>
        /// Algorithm used for signing, default is RS256.
        /// HS256/HS384/HS512 are symmetric algorithms, RS256/RS384/RS512 asymmetric.
        /// </summary>
        [DefaultValue(SigningAlgorithm.RS256)]
        public SigningAlgorithm SigningAlgorithm { get; set; }

        /// <summary>
        /// Value(s) for "sub" (Subject) Claim.
        /// Multiple claims with same keys/names can be added.
        /// Claims are optional.
        /// </summary>
        public JwtClaim[] Claims { get; set; }

        /// <summary>
        /// extra headers
        /// 
        /// usually there are no need to add these, but maybe eg. "kid" header would be nice.
        /// </summary>
        public JwtExtraHeader[] Headers { get; set; }
    }

    /// <summary>
    /// Options for method ParseToken().
    /// </summary>
    public class ParseOptions
    {
        /// <summary>
        /// Should the issuer (iss) validation be skipped.
        /// </summary>
        public bool SkipIssuerValidation { get; set; }

        /// <summary>
        /// Should audience (aud) validation be skipped.
        /// </summary>
        public bool SkipAudienceValidation { get; set; }

        /// <summary>
        /// Should lifetime (exp,nbf) validation be skipped.
        /// </summary>
        public bool SkipLifetimeValidation { get; set; }

        /// <summary>
        /// Should the Token be decrypted.
        /// </summary>
        public bool DecryptToken { get; set; }

        /// <summary>
        /// Decryption key, should be in PEM format.
        /// </summary>
        [UIHint(nameof(DecryptToken), "", true)]
        [PasswordPropertyText]
        public string DecryptionKey { get; set; }
    }

    /// <summary>
    /// The result object for method ParseToken().
    /// </summary>
    public class ParseResult
    {
        /// <summary>
        /// A claim-based identity parsed from the token.
        /// </summary>
        public ClaimsPrincipal ClaimsPrincipal { get; set; }

        /// <summary>
        /// A validated security token.
        /// </summary>
        public SecurityToken Token { get; set; }
    }

    /// <summary>
    /// Input parameters for ReadJwtToken task.
    /// </summary>
    public class ReadTokenInput
    {
        /// <summary>
        /// A 'JSON Web Token' (JWT) in JWS or JWE Compact Serialization Format.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("")]
        public string JwtToken { get; set; }
    }

    /// <summary>
    /// Input parameters for ValidateToken and ParseToken tasks.
    /// </summary>
    public class ValidateParseInput
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
        /// Either the JWT token or the Authorization header value through #trigger.data.httpHeaders["Authorization"].
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        [DefaultValue("#trigger.data.httpHeaders[\"Authorization\"]")]
        public string AuthHeaderOrToken { get; set; }

        /// <summary>
        /// The expected Audiences of the token, e.g. ClientId.
        /// </summary>
        [DefaultValue("")]
        [DisplayFormat(DataFormatString = "Text")]
        public string Audience { get; set; }

        /// <summary>
        /// The expected Issuer of the token.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("https://xyz.eu.auth0.com/")]
        public string Issuer { get; set; }

        /// <summary>
        /// The configuration source.
        /// </summary>
        [DefaultValue(ConfigurationSource.Static)]
        public ConfigurationSource ConfigurationSource { get; set; }

        /// <summary>
        /// The URL where the .well-known configuration for the issuer is located.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [UIHint(nameof(ConfigurationSource), "", ConfigurationSource.WellKnownConfigurationUrl)]
        [DefaultValue("https://xyz.eu.auth0.com/.well-known/openid-configuration")]
        public string WellKnownConfigurationUrl { get; set; }

        /// <summary>
        /// Static signing keys to use, can be found in the jwks_uri from the .well-known openid-configurations.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [UIHint(nameof(ConfigurationSource), "", ConfigurationSource.Static)]
        public string StaticJwksConfiguration { get; set; }
    }

    /// <summary>
    /// The enumerator for the configuration source.
    /// </summary>
    public enum ConfigurationSource
    {
        WellKnownConfigurationUrl,
        Static
    }

    /// <summary>
    /// Algorithms for signing.
    /// HS* are symmetric algorithms, RS* asymmetric.
    /// </summary>
    public enum SigningAlgorithm
    { RS256, RS384, RS512, HS256, HS384, HS512 }

    /// <summary>
    /// Class for describing of a single claim.
    /// </summary>
    public class JwtClaim
    {
        /// <summary>
        /// Claim key.
        /// </summary>
        public string ClaimKey { get; set; }

        /// <summary>
        /// Claim value.
        /// </summary>
        public string ClaimValue { get; set; }
    }

    public class JwtExtraHeader
    {
        /// <summary>
        /// Header key.
        /// </summary>
        public string HeaderKey { get; set; }

        /// <summary>
        /// Header value.
        /// </summary>
        public string HeaderValue { get; set; }

    }
}