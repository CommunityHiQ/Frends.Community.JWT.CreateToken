using System.ComponentModel;
using System.Security.Claims;

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

        public string ClaimValueType { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        public JwtClaim()
        {
            this.ClaimValueType = ClaimValueTypes.String;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">ClaimKey</param>
        /// <param name="value">ClaimValue</param>
        public JwtClaim(string key, string value): this()
        {
            this.ClaimKey = key;
            this.ClaimValue = value;
        }
    }
}
