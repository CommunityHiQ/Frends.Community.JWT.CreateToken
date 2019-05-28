using Microsoft.IdentityModel.Tokens;
using System;
using System.ComponentModel;

namespace Frends.Community.JWT
{
    /// <summary>
    /// JWT signing algorithm
    /// </summary>
    public enum JwtAlgorithm
    {
        /// <summary>
        /// RS256 algorithm
        /// </summary>
        RS256,
        /// <summary>
        /// ES256 algorithm
        /// </summary>
        ES256
    }

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

        /// <summary>
        /// Custom header entries, e.g. specify custom typ of kid
        /// </summary>
        public JwtClaim[] CustomHeaderEntries { get; set; }

        /// <summary>
        /// Algorithm used for JWT signing
        /// </summary>
        [DefaultValue(JwtAlgorithm.RS256)]
        public JwtAlgorithm Algorithm { get; set; }

        internal string GetAlgorithm()
        {
            switch (this.Algorithm)
            {
                case JwtAlgorithm.RS256:
                    return SecurityAlgorithms.RsaSha256;
                case JwtAlgorithm.ES256:
                    return SecurityAlgorithms.EcdsaSha256;
                default:
                    throw new Exception($"Unknown algorithm: {this.Algorithm}");
            }
        }
    }
}
