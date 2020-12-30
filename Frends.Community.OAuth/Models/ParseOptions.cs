namespace Frends.Community.OAuth.Models
{
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
}