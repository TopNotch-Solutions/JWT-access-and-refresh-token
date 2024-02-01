using System.ComponentModel.DataAnnotations;

namespace Authentication_role_based_authorization.Models
{
    public class RegistrationModel
    {
        [Key]
        public int RegisrationId { get; set; }
        [Required(ErrorMessage ="Username is required!")]
        public string Username { get; set; }
        [Required(ErrorMessage = "Name is required!")]
        public string FirstName { get; set; }
        public string LastName { get; set; }
        [Required(ErrorMessage = "Email is required!")]
        public string Email { get; set; }
        [Required(ErrorMessage = "Password is required!")]
        public string Password { get; set; }
    }
}
