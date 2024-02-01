using Authentication_role_based_authorization.Models;

namespace Authentication_role_based_authorization.Services
{
    public interface IAuthService
    {
        Task<(int, string)> Registration(RegistrationModel model, string role);
        Task<(int, string)> Login(LoginModel model);
        Task<TokenViewModel> GetRefreshToken(GetRefreshTokenViewModel model);
    }
}
