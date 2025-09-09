using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityService.SampleApi.Data;

public class AppDbContext : IdentityDbContext<IdentityUser<string>, IdentityRole<string>, string>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public AppDbContext() : base()
    {
    }
}
