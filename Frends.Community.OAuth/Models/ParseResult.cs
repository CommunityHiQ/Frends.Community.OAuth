using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace Frends.Community.OAuth.Models
{
    public class ParseResult
    {
        public ClaimsPrincipal ClaimsPrincipal { get; set; }
        public SecurityToken Token { get; set; }
    }
}