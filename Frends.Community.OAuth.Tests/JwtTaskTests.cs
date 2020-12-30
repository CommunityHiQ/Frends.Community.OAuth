using System;
using System.Linq;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Frends.Community.JWT.CreateToken.Tests
{
    [TestClass]
    public class JwtTaskTests
    {
        private static readonly string privateKey = @"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

        private static readonly string publicKey = @"-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEA6rikDZp8k0liADpV6S6rMjzhcl3HySlSgNZwBbh3fz8OQ/wxk6fQ
tiqw5zpuPpVjGibKPTmHayGR9CksE660RMv5GFl6OHpn7KhinvIiOe+SJ/vGOAU3
CVB4wGgWLJ9GZPDM6vp9i79IP2QSHTe3nyyTzhTAgtAlDv23cEO6hKaSFA+hNCkM
tC1HBLvMSdqNlS1Fg21kiSPpyYFZ8ddhjB4Az1SUto3hO0cWnL6hBcMoVenB68JF
18+T36nd8pMkitWs7xASUGxxA6OGhVLwHFKe4q0JlZ+VfvzYj2ir3qz4haUKMpPM
K2Qhvu70KUTNw4MMsk/poubto7g2U1GEs/4WRtZV0DFam8Uw22TJRMGHhGd1+rUn
U4/+0tzU+WXqJUeWBDubEMCJplHFmd/2MhEXXYNsV2nWZfybA8hETOHFX67/7daY
rJ14RaKymgjKMsBnRupur7C9eUic2Csl9SLGZQl7tP5XcFJ98uy7NwuohGr+H1Pe
Y3nMZ7rn5nvVYpRsNDPDMnTyq44phbbRCzNu8Imi33w55Y/gKVBY2lCn78IUbFtQ
ohUljJuLe10H1uKRMtpSDAcCumLnMu5pA7M33E7WLPmxeAbCUdHrXvWADuwsnHlR
zewJ+E1/wBhCidA2kfZVXWfhmQksv8CMPDUEOajm22Cj4l4is1qiWO0CAwEAAQ==
-----END RSA PUBLIC KEY-----";
        [TestMethod]
        public void CreateJwtTokenTest()
        {
            var token = JwtTask.CreateJwtToken(new CreateJwtTokenParameters
            {
                Audience = "aud",
                Expires = DateTime.Now.AddDays(7),
                Issuer = "frends",
                PrivateKey = privateKey,
                Claims = new []
                {
                    new JwtClaim { ClaimKey = "Name", ClaimValue = "Jefim4ik" }
                }
            });

            Assert.AreNotEqual(null, token);
            Assert.AreNotEqual(0, token.Length);

            // JWT tokens always have 2 dot separators between parts
            Assert.AreEqual(2, token.Count(o => o == '.'));
        }
    }
}
