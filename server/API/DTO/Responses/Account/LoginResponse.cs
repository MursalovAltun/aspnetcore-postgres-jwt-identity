using API.Services.Identity;

namespace API.DTO.Responses.Account
{
    public class LoginResponse
    {
        public string AccessToken { get; set; }
        public string Role { get; set; }
        public RefreshToken RefreshToken { get; set; }
        public string UserName { get; set; }
    }
}