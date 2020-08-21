using System.Threading;
using System.Threading.Tasks;
using Frends.Community.OAuth.Models;
using Microsoft.IdentityModel.Logging;
using NUnit.Framework;

namespace Frends.Community.OAuth.Tests
{
    [TestFixture]
    public class ValidatorTest
    {
        [OneTimeSetUp]
        public void Setup()
        {
            IdentityModelEventSource.ShowPII = true;
        }

        public const string AuthHeader =
            "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1UVXlSakkxUWtZelFUZzROVEkzT1RRelJUY3pSVFUzTlVRM056Z3lPRGhCUkRaQk5UVTNNdyJ9.eyJuaWNrbmFtZSI6InRlc3QiLCJuYW1lIjoidGVzdEBoaXEuZmkiLCJwaWN0dXJlIjoiaHR0cHM6Ly9zLmdyYXZhdGFyLmNvbS9hdmF0YXIvMzczNDM5NjExYmI0Yzk3YTFhMzg3Y2QxN2RlNGI3ZTU_cz00ODAmcj1wZyZkPWh0dHBzJTNBJTJGJTJGY2RuLmF1dGgwLmNvbSUyRmF2YXRhcnMlMkZ0ZS5wbmciLCJ1cGRhdGVkX2F0IjoiMjAxOC0xMC0xOFQxMDoxMDoxOS40NDNaIiwiaXNzIjoiaHR0cHM6Ly9mcmVuZHMuZXUuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDViYzg0MDRhOGY2NWZiN2YyOTM0Y2Q1MyIsImF1ZCI6ImZJVkxvdUtVWmloWGZZUDN0ZE85RDNkd2Q2Wk5TOUJlIiwiaWF0IjoxNTM5ODU3NDIzLCJleHAiOjE1Mzk4OTM0MjMsImF0X2hhc2giOiJZc0JXTTFmQ2V6LUZJRnZpNHdwejFBIiwibm9uY2UiOiIzLkJmWnBOd3AzSnUyd3pralhYMWdrUHZycHJ1NDEwMiJ9.RGbTdxUnTn1ohfVIU4YHwzYN9YGIzzraO2dB81zQRBI_I6NbTFTPBaGWizYHBnMEQzDSnqkqHxyaa-tZZnLrFtDfTOPfSs6RCEJbwmMaNQFiEPz3ZO_dZb8jomNXcAWqOco-2c22xoLpn4b4pAnWg9muricZNlnwPR-1YOYjWt2-5s3xVVPNopyYum33AQiScOVYzlbaT388r-rEOL1FWrdYybiXR5TJcEsaeQOM57CNgcyJX8xBy7J-8R8Yf1ZfliLXIS70K3lhrLSqpVUGFFeyVZICSXURPL44R9VYBCl4YCEb4zKM-wOJyDmc0VR0rwgsY5E1h6yCtsiNKH74rw";

        [Test]
        public async Task Validator_ShouldAcceptValidTokenWithWellKnownUri()
        {
            var result = await Validator.ParseToken(new ValidateInput
            {
                Issuer = "https://frends.eu.auth0.com/",
                Audience = "fIVLouKUZihXfYP3tdO9D3dwd6ZNS9Be",
                AuthHeaderOrToken = AuthHeader,
                ConfigurationSource = ConfigurationSource.WellKnownConfigurationUrl,
                WellKnownConfigurationUrl = "https://frends.eu.auth0.com/.well-known/openid-configuration"
                },
                new ParseOptions{SkipLifetimeValidation = true}, // The token will be expired
                CancellationToken.None).ConfigureAwait(false);
        }

        private const string JwkKeys =
            "{\"keys\":[{\"alg\":\"RS256\",\"kty\":\"RSA\",\"use\":\"sig\",\"x5c\":[\"MIIDATCCAemgAwIBAgIJQSARkr+uIp3QMA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMTE2ZyZW5kcy5ldS5hdXRoMC5jb20wHhcNMTgwMzI2MTEyNjU3WhcNMzExMjAzMTEyNjU3WjAeMRwwGgYDVQQDExNmcmVuZHMuZXUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+O62mHn2qLVvdaTo9mVtRQTLOCxpBPS3HTFhSJIikDZ77jhyRJjLPGUa6udlgH36Ts8axRvcPHBq2i+Dah0tnbchNJwT7nQlpnB2CuhC+JCntffoA+q5VcJhvaPRBbI/D3QnjXlXY4n7mZKGovfQlFXlNScHI/A6YQ55MPGhui9Su0YLhNiC7wELTmR2L+rAyJJ+Tl0u1g+gLNHsTF18iJFfy6yUBLdtAgT/HeIyLblisdMrp8SMsOoWKQwUt4HA3sjF0FqyO8Rjz6RwOh6FpUTWGbUtHS/bV76QooMSfyi9tIMO5ISwpvFWPlDzIUxdqrBxJzPQUtlGkxWE41MBewIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSwaPu0o5G98jCQF1FAD68sJtRcYjAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAJpBr0lbEYrhTHy2PzCaOtJICzal2oK2TCJC+T1F2Bx2XFF4XxYFwwa1W6cVkoM8NvutfnYgm1qR9JSIjIKw/Ks6kpJlVb3O7RK/3lARkxI09vfoF3OWMzh31uW6k4zZX9jDYIvdEAa1l3ROImfYY1eqo5L8rUJZdMf0h368ziyUYyRDGrrGSvWo9FDgQRKZ8BjJfZKZDjp100Bml+siYi/Rl6RTdTKpQHV34VYAEdw5RHRxMm1zEm1ebAngrDKArYWaMws3cMbKnPTyX7F3To9tLnijwsjJInmbUXo/KnXPsizJaiomNCXEw48f3oPoG9tFlItRqZzatv4PeMix8p8=\"],\"n\":\"-O62mHn2qLVvdaTo9mVtRQTLOCxpBPS3HTFhSJIikDZ77jhyRJjLPGUa6udlgH36Ts8axRvcPHBq2i-Dah0tnbchNJwT7nQlpnB2CuhC-JCntffoA-q5VcJhvaPRBbI_D3QnjXlXY4n7mZKGovfQlFXlNScHI_A6YQ55MPGhui9Su0YLhNiC7wELTmR2L-rAyJJ-Tl0u1g-gLNHsTF18iJFfy6yUBLdtAgT_HeIyLblisdMrp8SMsOoWKQwUt4HA3sjF0FqyO8Rjz6RwOh6FpUTWGbUtHS_bV76QooMSfyi9tIMO5ISwpvFWPlDzIUxdqrBxJzPQUtlGkxWE41MBew\",\"e\":\"AQAB\",\"kid\":\"MTUyRjI1QkYzQTg4NTI3OTQzRTczRTU3NUQ3NzgyODhBRDZBNTU3Mw\",\"x5t\":\"MTUyRjI1QkYzQTg4NTI3OTQzRTczRTU3NUQ3NzgyODhBRDZBNTU3Mw\"}]}";
        [Test]
        public async Task Validator_ShouldAcceptValidTokenWithStaticConfiguration()
        {
            var result = await Validator.ParseToken(new ValidateInput
                {
                    Issuer = "https://frends.eu.auth0.com/",
                    Audience = "fIVLouKUZihXfYP3tdO9D3dwd6ZNS9Be",
                    AuthHeaderOrToken = AuthHeader,
                    ConfigurationSource = ConfigurationSource.Static,
                    StaticJwksConfiguration = JwkKeys,

                },
                new ParseOptions{SkipLifetimeValidation = true}, 
                CancellationToken.None).ConfigureAwait(false);
        }
    }
}
