# Frends.Community.JWT.CreateToken
Frends task for creating signed JWT tokens.

- [Installing](#installing)
- [Tasks](#tasks)
  - [CreateJwtToken](#CreateJwtToken)
- [License](#license)
- [Building](#building)
- [Contributing](#contributing)
- [Change Log](#change-log)

# Installing
You can install the task via FRENDS UI Task View or you can find the nuget package from the following nuget feed
https://www.myget.org/F/frends-community/api/v3/index.json

Tasks
=====

## CreateJwtToken

### Parameters

| Property             | Type                 | Description                          | Example |
| ---------------------| ---------------------| ------------------------------------ | ----- |
| Issuer | string | Value for "iss" | `COOL_ISSUER` |
| Audience | string | Value for "aud" | `COOL_AUDIENCE` |
| Expires | DateTime? | Value for "exp" | `DateTime.Now.AddDays(7)` |
| NotBefore | DateTime? | Value for "nbf" | `DateTime.Now.AddDays(7)` |
| PrivateKey | string | Private key in PEM format | See https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
| Claims | JwtClaim[] | Claims for the token. If you need an array with values then just add multiple claims with same keys/names. | `[`<br/>`{ "Name", "John Doe" },`<br/>`{ "EMail", "john@example.com" },`<br/>`{ "Roles", "admin" },`<br/>`{ "Roles", "user" }`<br/>`]`

### Result
Result contains the JWT token signed with the provided private key.

# License

This project is licensed under the MIT License - see the LICENSE file for details

# Building

Clone a copy of the repo

`git clone https://github.com/CommunityHiQ/Frends.Community.JWT.CreateToken`

Restore dependencies

`nuget restore`

Rebuild the project

Run Tests with MSTest. Tests can be found under

`Frends.Community.JWT.CreateToken.Tests\bin\Release\Frends.Community.JWT.CreateToken.Tests.dll`

Create a nuget package

`nuget pack Frends.Community.JWT.CreateToken.nuspec`

# Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

1. Fork the repo on GitHub
2. Clone the project to your own machine
3. Commit changes to your own branch
4. Push your work back up to your fork
5. Submit a Pull request so that we can review your changes

NOTE: Be sure to merge the latest from "upstream" before making a pull request!

# Change Log

| Version             | Changes                 |
| ---------------------| ---------------------|
| 1.0.0 | Initial version of CreateJwtToken task |