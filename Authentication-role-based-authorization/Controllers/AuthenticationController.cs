using Authentication_role_based_authorization.Models;
using Authentication_role_based_authorization.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Authentication_role_based_authorization.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthService authService;
        private readonly ILogger<AuthenticationController> logger;
        private readonly IConfiguration configuration;
        private readonly UserManager<ApplicationUse> userManager;
        public AuthenticationController(IAuthService authService, ILogger<AuthenticationController> logger, IConfiguration configuration, UserManager<ApplicationUse> userManager)
        {
            this.authService = authService;
            this.logger = logger;
            this.configuration = configuration;
            this.userManager = userManager;
        }
        [Route("login")]
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            try
            {
                if(!ModelState.IsValid)
                {
                    return BadRequest("Invalid data");
                }
                var (status, message) = await authService.Login(model);
                if(status == 0)
                {
                    return BadRequest(message);
                }
                return Ok(message);
            }catch (Exception ex)
            {
                logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
        [Route("register")]
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Register(RegistrationModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest("Invalid data");
                }
                var (status, message) = await authService.Registration(model, UserRoles.Admin);
                if(status == 0)
                {
                    return BadRequest(message);
                }
                return CreatedAtAction(nameof(Register), model);
            }catch(Exception ex)
            {
                logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
        [Route("user-list")]
        [Authorize(Roles = "Admin")]
        [HttpGet]
        public async Task<IActionResult> GetList()
        {
            var userList = await Task.FromResult(new string[] { "Paulus", "Messi", "Ronaldo", "Greenwood" });
            return Ok(userList);
        }
        [AllowAnonymous]
        [HttpPost]
        [Route("Refresh-Token")]
        public async Task<IActionResult> RefreshToken(GetRefreshTokenViewModel model)
        {
            try
            {
                if(model is null)
                {
                    return BadRequest("Invalid client request");
                }
                var result = await authService.GetRefreshToken(model);
                if(result.StatusCode == 0)
                {
                    return BadRequest(result.StatusMessage);
                }
                return Ok(result);
            }catch (Exception ex)
            {
                logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
        [Authorize]
        [HttpPost]
        [Route("Revoke/{username}")]
        public async Task<IActionResult> Revoke(string username)
        {
            var user = await userManager.FindByNameAsync(username);
            if(user == null)
            {
                return BadRequest("Invalid username");
            }
            user.RefreshToken = null;
            await userManager.UpdateAsync(user);
            return Ok("Success");
        }
        [Authorize]
        [HttpPost]
        [Route("Revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
           var users = userManager.Users.ToList();
            foreach (var user in users) {
                user.RefreshToken = null;
                await userManager.UpdateAsync(user);
            }
            return Ok("Success");
        }
    }
}
