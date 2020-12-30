using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
namespace Frends.Community.OAuth.Models
{
    public class ReadTokenInput
    {
        /// <summary>
        /// A 'JSON Web Token' (JWT) in JWS or JWE Compact Serialization Format.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("")]
        public string JWTToken { get; set; }
    }
}