using FakeAiChecker.Data;
using FakeAiChecker.Models;
using FakeAiChecker.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace FakeAiChecker.Helpers
{
    public static class AdminInitializer
    {
        public static async Task EnsureAdminUserExists(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var authService = scope.ServiceProvider.GetRequiredService<AuthService>();
            var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
            var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();

            try
            {
                // Check if any admin user exists
                var adminExists = await context.Users.AnyAsync(u => u.Role == "Admin");

                if (!adminExists)
                {
                    logger.LogInformation("No admin user found. Creating default admin user.");

                    // Use credentials from configuration or environment variables (for security)
                    string adminUsername = configuration["AdminSetup:DefaultUsername"] ?? "g4stly";
                    string adminPassword = configuration["AdminSetup:DefaultPassword"] ?? "123";

                    var registerModel = new RegisterModel
                    {
                        Username = adminUsername,
                        Password = adminPassword,
                        ConfirmPassword = adminPassword
                    };

                    var result = await authService.RegisterAsync(registerModel, "system", "system-initialization");

                    if (result != null)
                    {
                        logger.LogInformation("Default admin user created successfully.");
                    }
                    else
                    {
                        logger.LogError("Failed to create default admin user.");
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while creating the default admin user.");
            }
        }
    }
}
