# Frends.Community.OAuth

FRENDS community Task for validating and parsing OAuth JWT tokens

- [Frends.Community.OAuth](#frendscommunityoauth)
- [Installing](#installing)
- [Tasks](#tasks)
    - [Validate](#validate)
        - [Input](#input)
        - [Output](#output)
    - [ParseToken](#parsetoken)
        - [Input](#input)
        - [Options](#options)
        - [Output](#output)
- [Building](#building)
- [Contributing](#contributing)
- [Change Log](#change-log)

# Installing

You can install the task via FRENDS UI Task View or you can find the nuget package from the following nuget feed.
'https://www.myget.org/F/frends-community/api/v3/index.json'

# Tasks

## Validate

Validates the provided OAuth JWT token or Authorization header

### Input

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| AuthHeaderOrToken | String | Either the JWT token or the AuthHeader through #trigger.data.httpHeaders["Authorization"] | eyJ0eXAi... |
| Audience | String | The expected Audiences of the token, e.g. ClientId | fIVLouKUZihXfYP3... |
| Issuer | String | The expected Issuer of the token | https://example.eu.auth0.com |
| ConfigurationSource | enum | Option whether to use .well-known or a static jwks configuration | WellKnownConfigurationUrl |
| WellKnownConfigurationUrl | String | .well-known configuration URL | https://example.eu.auth0.com/.well-known/openid-configuration |
| StaticJwksConfiguration | String | Staticly provided public keys used to sign the token | {\"keys\":[{\"alg\":\"RS256\",\"kty\":\"RSA\",\"use\":\"sig\",\"x5c\":[\"MIIDATC... |

### Output

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| ClaimPrincipal | [System.Security.Claims.ClaimsPrincipal](https://docs.microsoft.com/en-us/dotnet/api/system.security.claims.claimsprincipal?view=netframework-4.7.2) | The ClaimsPrincipal parsed from the token | |
| Token | [System.IdentityModel.Tokens.JwtSecurityToken](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.jwtsecuritytoken(v=vs.114).aspx) | The token |  |

## ParseToken

Parses the provided OAuth JWT token or Authorization header with the option of skipping validations

### Input

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| AuthHeaderOrToken | String | Either the JWT token or the AuthHeader through #trigger.data.httpHeaders["Authorization"] | eyJ0eXAi... |
| Audience | String | The expected Audiences of the token, e.g. ClientId | fIVLouKUZihXfYP3... |
| Issuer | String | The expected Issuer of the token | https://example.eu.auth0.com |
| ConfigurationSource | enum | Option whether to use .well-known or a static jwks configuration | WellKnownConfigurationUrl |
| WellKnownConfigurationUrl | String | .well-known configuration URL | https://example.eu.auth0.com/.well-known/openid-configuration |
| StaticJwksConfiguration | String | Staticly provided public keys used to sign the token | {\"keys\":[{\"alg\":\"RS256\",\"kty\":\"RSA\",\"use\":\"sig\",\"x5c\":[\"MIIDATC... |

### Options

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| SkipIssuerValidation | bool | Should issuer validation be skipped | false |
| SkipAudienceValidation | bool | Should audience validation be skipped | false |
| SkipLifetimeValidation | bool | Should lifetime validation be skipped | false |

### Output

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| ClaimPrincipal | [System.Security.Claims.ClaimsPrincipal](https://docs.microsoft.com/en-us/dotnet/api/system.security.claims.claimsprincipal?view=netframework-4.7.2) | The ClaimsPrincipal parsed from the token | |
| Token | [System.IdentityModel.Tokens.JwtSecurityToken](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.jwtsecuritytoken(v=vs.114).aspx) | The token. If you want the token as a string use .ToString() method (e.g. #result.Token.ToString()) |  |

# Building
Clone a copy of the repo

`git clone https://github.com/CommunityHiQ/Frends.Community.OAuth.git`

Restore dependencies

`nuget restore Frends.Community.OAuth`

Rebuild the project

Run unit tests

Create a nuget package

`nuget pack Frends.Community.OAuth.nuspec`

# Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

1. Fork the repo on GitHub
2. Clone the project to your own machine
3. Commit changes to your own branch
4. Push your work back up to your fork
5. Submit a Pull request so that we can review your changes

NOTE: Be sure to merge the latest from "upstream" before making a pull request!

# Change Log

| Version | Changes |
| ----- | ----- |
| 1.0.0 | Initial version of OAuth Task |
