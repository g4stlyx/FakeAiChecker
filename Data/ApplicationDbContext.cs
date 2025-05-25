using Microsoft.EntityFrameworkCore;
using FakeAiChecker.Models;

namespace FakeAiChecker.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<ScanResult> ScanResults { get; set; }
        public DbSet<SecretFinding> SecretFindings { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<User> Users { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure the relationship between ScanResult and SecretFinding
            modelBuilder.Entity<SecretFinding>()
                .HasOne(sf => sf.ScanResult)
                .WithMany(sr => sr.SecretFindings)
                .HasForeignKey(sf => sf.ScanResultId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
