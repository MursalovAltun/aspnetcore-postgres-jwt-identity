using System;
using System.Security.Claims;

namespace API.Services.Identity
{
    public interface IJwtGeneratorService
    {
        JwtAuthResult GenerateTokens(string username, Claim[] claims, DateTime now);
        JwtAuthResult Refresh(string refreshToken, string accessToken, DateTime now);
        void RemoveExpiredRefreshTokens(DateTime now);
        void RemoveRefreshTokenByUserName(string userName);
    }
}