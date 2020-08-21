using System;
using System.ComponentModel;

namespace Frends.Community.JWT
{
    /// <summary>
    /// Create JWT token parameters
    /// </summary>
    public class CreateJwtTokenParameters
    {
        /// <summary>
        /// Value for "iss"
        /// </summary>
        [DefaultValue("ISSUER")]
        public string Issuer { get; set; }

        /// <summary>
        /// Value for "aud"
        /// </summary>
        [DefaultValue("AUDIENCE")]
        public string Audience { get; set; }

        /// <summary>
        /// Value for "exp"
        /// </summary>
        [DefaultValue("DateTime.Now.AddDays(7)")]
        public DateTime? Expires { get; set; }

        /// <summary>
        /// Value for "nbf"
        /// </summary>
        [DefaultValue("DateTime.Now.AddDays(1)")]
        public DateTime? NotBefore { get; set; }

        /// <summary>
        /// Private key for singing. The key should be in PEM format
        /// </summary>
        [PasswordPropertyText]
        public string PrivateKey { get; set; }

        /// <summary>
        /// Claims for the token. If you need an array with values then just add multiple claims with same keys/names.
        /// </summary>
        public JwtClaim[] Claims { get; set; }
    }
}
