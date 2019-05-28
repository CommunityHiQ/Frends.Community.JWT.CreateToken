using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using PemUtils;

namespace Frends.Community.JWT
{
    /// <summary>
    /// JWT Task
    /// </summary>
    public class JwtTask
    {
        /// <summary>
        /// Create a JWT token with specified parameters. Documentation: https://github.com/CommunityHiQ/Frends.Community.JWT.CreateToken
        /// </summary>
        /// <param name="parameters">Parameters for the token creation</param>
        /// <returns>string</returns>
        public static string CreateJwtToken(CreateJwtTokenParameters parameters)
        {
            var handler = new JwtSecurityTokenHandler();
            
            var signingCredentials = CreateSigningCredentials(parameters);

            var claims = new ClaimsIdentity();
            if (parameters.Claims != null)
            {
                foreach (var claim in parameters.Claims)
                {
                    var valueType = string.IsNullOrWhiteSpace(claim.ClaimValueType)
                        ? ClaimValueTypes.String
                        : claim.ClaimValueType;
                    claims.AddClaim(new Claim(claim.ClaimKey, claim.ClaimValue, valueType));
                }
            }

            // Create JWT
            var token = handler.CreateJwtSecurityToken(new SecurityTokenDescriptor
            {
                Issuer = parameters.Issuer,
                Audience = parameters.Audience,
                Expires = parameters.Expires,
                NotBefore = parameters.NotBefore,
                Subject = claims,
                SigningCredentials = signingCredentials,
            });
            
            if (parameters.CustomHeaderEntries != null)
            {
                foreach(var customHeaderEntry in parameters.CustomHeaderEntries)
                {
                    token.Header[customHeaderEntry.ClaimKey] = customHeaderEntry.ClaimValue;
                }
            }
            

            return handler.WriteToken(token);
        }

        private static SigningCredentials CreateSigningCredentials(CreateJwtTokenParameters parameters)
        {
            switch(parameters.Algorithm)
            {
                case JwtAlgorithm.RS256:
                    using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(parameters.PrivateKey)))
                    using (var reader = new PemReader(stream))
                    {
                        var rsaParameters = reader.ReadRsaKey();
                        var rsaSecurityKey = new RsaSecurityKey(rsaParameters);
                        return new SigningCredentials(rsaSecurityKey, parameters.GetAlgorithm());
                    }
                case JwtAlgorithm.ES256:
                    var privateKeyStr = parameters.PrivateKey
                        .Replace("-----BEGIN PRIVATE KEY-----", "")
                        .Replace("-----END PRIVATE KEY-----", "")
                        .Trim();
                    CngKey key = CngKey.Import(Convert.FromBase64String(privateKeyStr), CngKeyBlobFormat.Pkcs8PrivateBlob);
                    var ecdsaCng = new ECDsaCng(key);
                    return new SigningCredentials(new ECDsaSecurityKey(ecdsaCng), parameters.GetAlgorithm());
                default:
                    throw new NotSupportedException($"Unknown algorithm {parameters.Algorithm}");
            }
        }

        private static byte[] FromUrlBase64String(string input)
        {
            input = input.Replace('-', '+').Replace('_', '/');

            while (input.Length % 4 != 0)
            {
                input += "=";
            }

            return Convert.FromBase64String(input);
        }

        private static ECDsa GetECDsa(string privateKey)
        {
            CngKey key = CngKey.Import(Convert.FromBase64String(privateKey), CngKeyBlobFormat.Pkcs8PrivateBlob);
            return new ECDsaCng(key);
        }
    }
}
