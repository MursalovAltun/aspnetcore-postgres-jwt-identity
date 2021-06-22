using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace API.DTO.Requests.Account
{
    public class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class JwtTokenParametersProvider : JwtSecurityTokenHandler
    {
    }
}