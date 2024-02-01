using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Authentication_role_based_authorization.Models
{
    public class ApplicationUse:IdentityUser
    {
        public string FirstName { get; set;}
        public string LastName { get; set;}
        public string RefreshToken { get; set;}
        public DateTime RefreshTokenExpiryTime { get; set;}
    }
}
