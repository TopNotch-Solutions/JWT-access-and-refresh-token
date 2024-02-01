using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Authentication_role_based_authorization.Models
{
    public class AppDbContext : IdentityDbContext<ApplicationUse>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options):base(options) 
        {
            
        }
        //public DbSet<RegistrationModel> registrations { get; set; }
    }
}
