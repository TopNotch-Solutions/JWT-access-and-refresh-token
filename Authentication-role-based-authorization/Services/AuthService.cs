using Authentication_role_based_authorization.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Authentication_role_based_authorization.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUse> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;

        public AuthService(UserManager<ApplicationUse> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
        }
        async Task<(int, string)> IAuthService.Registration(RegistrationModel model, string role)
        {
            var userExists = await userManager.FindByNameAsync(model.Username);
            if(userExists != null)
            {
                return (0, "Username already taken");
            }
            ApplicationUse user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };
            var createUserResult = await userManager.CreateAsync(user, model.Password);
            if (!createUserResult.Succeeded)
            {
                foreach (var error in createUserResult.Errors)
                {
                    
                    Console.WriteLine($"User creation error: {error.Description}");
                }
                return (0, "User creation failed! Please check user details and try again.");
            }
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
            if (!await roleManager.RoleExistsAsync(role))
                await userManager.AddToRoleAsync(user, role);
            return (1, "User successfully created!");
        }
        async Task<(int, string)> IAuthService.Login(LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.Username);
            if(user == null)
            {
                return (0, "Invalid username");
            }
            if(!await userManager.CheckPasswordAsync(user, model.Password))
            {
                return (0, "Invalid password");
            }
            var userRoles = await userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, model.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            foreach(var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole.ToString()));
            }
            string token = GenerateToken(authClaims);
            return (1, token);
        }
        async Task<TokenViewModel> IAuthService.GetRefreshToken(GetRefreshTokenViewModel model)
        {
            TokenViewModel tokenViewModel = new();
            var principal = GetPrincipalFromExpiredToken(model.AcceptedToken);
            string username = principal.Identity.Name;
            var user = await userManager.FindByNameAsync(username);
            
            if(user == null || user.RefreshToken != model.RefreshToken || user.RefreshTokenExpiryTime <=DateTime.Now)
            {
                tokenViewModel.StatusCode = 0;
                tokenViewModel.StatusMessage = "Invalid access token or refresh token!";
                return tokenViewModel;
            }
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())    
            };
            var newAccessToken = GenerateToken(authClaims);
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await userManager.UpdateAsync(user);

            tokenViewModel.StatusCode = 1;
            tokenViewModel.StatusMessage = "Success";
            tokenViewModel.AccessToken = newAccessToken;
            tokenViewModel.RefreshToken = newRefreshToken;

            return tokenViewModel;
        }

        private string GenerateToken(IEnumerable<Claim> claims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWTKey:Secret"]));
            var tokenExpiryTimeInHour = Convert.ToInt64(configuration["JWTKey:TokenExpiryTimeHour"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = configuration["JWTKey:ValidIssuer"],
                Audience = configuration["JWTKey:ValidAudience"],
                Expires = DateTime.UtcNow.AddMinutes(1),
                SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
                Subject = new ClaimsIdentity(claims),
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey =true,
                ValidateLifetime = false,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWTKey:Secret"]))
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if(securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }
            return principal;
        }
    }
}
