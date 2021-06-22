using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using API.DTO.Requests.Account;
using API.DTO.Responses.Account;
using API.Models.Identity;
using API.Services.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Claim = System.Security.Claims.Claim;

namespace API.Controllers
{
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IJwtGeneratorService _jwtGeneratorService;

        public AccountController(UserManager<User> userManager,
            SignInManager<User> signInManager,
            IJwtGeneratorService jwtGeneratorService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtGeneratorService = jwtGeneratorService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null) return Unauthorized();
            
            var signInResult = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);

            if (signInResult.Succeeded)
            {
                var role = await _userManager.GetRolesAsync(user);
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Role, role.First())
                };

                var tokens = _jwtGeneratorService.GenerateTokens(user.UserName, claims, DateTime.Now);
                
                return Ok(new LoginResponse
                {
                    AccessToken = tokens.AccessToken,
                    RefreshToken = tokens.RefreshToken,
                    Role = role.First(),
                    UserName = user.UserName
                });   
            }

            return Unauthorized();
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var registerResult = await _userManager.CreateAsync(new User
            {
                Email = request.Email,
                UserName = request.Email,
            }, request.Password);

            if (registerResult.Succeeded)
            {
                return Ok(new RegisterResponse
                {
                    AccessToken = "test"
                });
            }

            return BadRequest();
        }
        
        [Authorize]
        [HttpPost("logout")]
        public ActionResult Logout()
        {
            var userName = User.Identity.Name;
            _jwtGeneratorService.RemoveRefreshTokenByUserName(userName);
            return Ok();
        }
        
        [HttpPost("refresh-token")]
        [Authorize]
        public async Task<ActionResult> RefreshToken([FromBody] string refreshToken)
        {
            try
            {
                var userName = User.Identity.Name;

                if (string.IsNullOrWhiteSpace(refreshToken))
                {
                    return Unauthorized();
                }

                var accessToken = await HttpContext.GetTokenAsync("Bearer", "access_token");
                
                var jwtResult = _jwtGeneratorService.Refresh(refreshToken, accessToken, DateTime.Now);
                return Ok(new LoginResponse
                {
                    UserName = userName,
                    Role = User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty,
                    AccessToken = jwtResult.AccessToken,
                    RefreshToken = jwtResult.RefreshToken
                });
            }
            catch (SecurityTokenException e)
            {
                return Unauthorized(e.Message); // return 401 so that the client side can redirect the user to login page
            }
        }
    }
}