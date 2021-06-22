using System;
using System.Reflection;
using API.Models;
using API.Models.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace API
{
    public class
        PostgreIdentityContext : IdentityDbContext<User, Role, Guid, Claim, UserRole, UserLogin, RoleClaim, UserToken>
    {
        public DbSet<Todo> Todos { get; set; }
        
        public PostgreIdentityContext(DbContextOptions<PostgreIdentityContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetAssembly(typeof(Startup)));

            base.OnModelCreating(modelBuilder);
        }
    }
}