# Frends.Community.OAuth

frends Community Task for OAuth.

[![Actions Status](https://github.com/CommunityHiQ/Frends.Community.OAuth/workflows/PackAndPushAfterMerge/badge.svg)](https://github.com/CommunityHiQ/Frends.Community.OAuth/actions) ![MyGet](https://img.shields.io/myget/frends-community/v/Frends.Community.OAuth) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 

- [Installing](#installing)
- [Tasks](#tasks)
     - [CreateJwtToken](#CreateJwtToken)
     - [ParseToken](#ParseToken)
     - [ReadToken](#ReadToken)
     - [Validate](#Validate)
- [Building](#building)
- [Contributing](#contributing)
- [Change Log](#change-log)

# Installing

You can install the Task via frends UI Task View or you can find the NuGet package from the following NuGet feed
https://www.myget.org/F/frends-community/api/v3/index.json and in Gallery view in MyGet https://www.myget.org/feed/frends-community/package/nuget/Frends.Community.OAuth

# Tasks

## CreateJwtToken

Task creates a signed JWT token.

### Parameters

| Property             | Type                 | Description                          | Example |
| ---------------------| ---------------------| ------------------------------------ | ----- |
| Issuer | `string` | Principal that issued the JWT. | `COOL_ISSUER` |
| Audience | `string` | The recipient(s) the JWT is intended for. | `COOL_AUDIENCE` |
| Expires | `DateTime?` | The expiration time on or after which the JWT must not be accepted for processing. | `DateTime.Now.AddDays(7)` |
| NotBefore | `DateTime?` | The time before which the JWT must not be accepted for processing. | `DateTime.Now.AddDays(7)` |
| PrivateKey | `string` | Private key in PEM format | See https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
| Claims | `JwtClaim[]` | Claim(s) that identifiy the principal that is the subject of the JWT. Multiple claims with same keys/names can be added. Claims are optional. | `[`<br/>`{ "Name", "John Doe" },`<br/>`{ "EMail", "john@example.com" },`<br/>`{ "Roles", "admin" },`<br/>`{ "Roles", "user" }`<br/>`]`

#### JwtClaim

Each identifies the principal that is the subject of the JWT.

| Property             | Type                 | Description                          | Example |
| ---------------------| ---------------------| ------------------------------------ | ----- |
| ClaimKey | `string` | Key value for the claim. | `COOL_ISSUER` |
| ClaimValue | `string` | The value paired with the given key. | `COOL_AUDIENCE` |

### Result

| Type | Description | Example |
| ------|-------------|---------|
| `string` | The JWT token signed with the provided private key. | |

## ParseToken

Parses the provided OAuth JWT token or Authorization header. There is an option to skip validations.

### Input

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| AuthHeaderOrToken | `string` | Either the JWT token or the AuthHeader through #trigger.data.httpHeaders["Authorization"] | `eyJ0eXAi...` |
| Audience | `string` | The expected Audiences of the token, e.g. ClientId | `fIVLouKUZihXfYP3...` |
| Issuer | `string` | The expected Issuer of the token | `https://example.eu.auth0.com` |
| ConfigurationSource | enum<WellKnownConfigurationUrl, Static> | Option whether to use .well-known or a static jwks configuration | WellKnownConfigurationUrl |
| WellKnownConfigurationUrl | `string` | .well-known configuration URL | `https://example.eu.auth0.com/.well-known/openid-configuration` |
| StaticJwksConfiguration | `string` | Staticly provided public keys used to sign the token | `{\"keys\":[{\"alg\":\"RS256\",\"kty\":\"RSA\",\"use\":\"sig\",\"x5c\":[\"MIIDATC...` |

### Options

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| SkipIssuerValidation | `bool` | Should issuer validation be skipped | `false` |
| SkipAudienceValidation | `bool` | Should audience validation be skipped | `false` |
| SkipLifetimeValidation | `bool` | Should lifetime validation be skipped | `false` |

### Result

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| ClaimPrincipal | [ClaimsPrincipal](https://docs.microsoft.com/en-us/dotnet/api/system.security.claims.claimsprincipal?view=netframework-4.7.2) | The ClaimsPrincipal parsed from the token. | |
| Token | [JwtSecurityToken](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.jwtsecuritytoken(v=vs.114).aspx) | The validated security token. If you want the token as a string use .ToString() method (e.g. #result.Token.ToString()) |  |

## ReadToken

Parses a string into an JwtSecurityToken.

### Input

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| JWTToken | `string` | A 'JSON Web Token' (JWT) in JWS or JWE Compact Serialization Format. | `eyJ0eXAi...` |

### Result

| Type | Description | Example |
| ------|-------------|---------|
|  [JwtSecurityToken](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.jwt.jwtsecuritytoken?view=azure-dotnet) | The security token. If you want the token as a string use .ToString() method (e.g. #result.ToString()) | |

## Validate

Validates the provided OAuth JWT token or the authorization header.

### Input

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| AuthHeaderOrToken | `string` | Either the JWT token or the AuthHeader through #trigger.data.httpHeaders["Authorization"] | `eyJ0eXAi...` |
| Audience | `string` | The expected Audiences of the token, e.g. ClientId | `fIVLouKUZihXfYP3...` |
| Issuer | `string` | The expected Issuer of the token | `https://example.eu.auth0.com` |
| ConfigurationSource | enum<WellKnownConfigurationUrl, Static> | Option whether to use .well-known or a static jwks configuration | WellKnownConfigurationUrl |
| WellKnownConfigurationUrl | `string` | .well-known configuration URL | `https://example.eu.auth0.com/.well-known/openid-configuration` |
| StaticJwksConfiguration | `string` | Staticly provided public keys used to sign the token | `{\"keys\":[{\"alg\":\"RS256\",\"kty\":\"RSA\",\"use\":\"sig\",\"x5c\":[\"MIIDATC...` |

### Result

The result is an object with following properties

| Property | Type | Description | Example |
| ---------|------|-------------|---------|
| ClaimPrincipal | [ClaimsPrincipal](https://docs.microsoft.com/en-us/dotnet/api/system.security.claims.claimsprincipal?view=netframework-4.7.2) | The ClaimsPrincipal parsed from the token. | |
| Token | [JwtSecurityToken](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.jwtsecuritytoken(v=vs.114).aspx) | The validated security token. If you want the token as a string use .ToString() method (e.g. #result.Token.ToString()) |  |

# Building

Clone a copy of the repository

`git clone https://github.com/CommunityHiQ/Frends.Community.OAuth.git`

Rebuild the project

`dotnet build`

Run tests

`dotnet test`

Create a NuGet package

`dotnet pack --configuration Release`

# Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

1. Fork the repository on GitHub
2. Clone the project to your own machine
3. Commit changes to your own branch
4. Push your work back up to your fork
5. Submit a Pull request so that we can review your changes

NOTE: Be sure to merge the latest from "upstream" before making a pull request!

# Change Log

| Version | Changes |
| ------- | ------- |
| 1.0.0   | [Frends.Community.OAuth.Validate](https://github.com/CommunityHiQ/Frends.Community.OAuth.Validate) and [Frends.Community.JWT.CreateToken](https://github.com/CommunityHiQ/Frends.Community.JWT.CreateToken) merged as one task collection. |
| 2.0.0   | Renaming ReadToken to ReadJwtToken. |
| 2.1.0   | Tasks now imports correctly to frends. |
| 2.1.0   | Tasks now correctly saves in .Net Standard 2.0 processes. |

