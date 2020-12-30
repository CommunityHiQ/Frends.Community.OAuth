namespace Frends.Community.JWT
{
    /// <summary>
    /// Class for describing of a single claim
    /// </summary>
    public class JwtClaim
    {
        /// <summary>
        /// Claim key
        /// </summary>
        public string ClaimKey { get; set; }

        /// <summary>
        /// Claim value
        /// </summary>
        public string ClaimValue { get; set; }
    }
}
