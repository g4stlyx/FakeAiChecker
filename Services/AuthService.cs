using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using FakeAiChecker.Data;
using FakeAiChecker.Models;

namespace FakeAiChecker.Services
{
    public class AuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AuthService> _logger;
        private readonly JwtSettings _jwtSettings;
        private readonly AuditService _auditService;
        
        private readonly string _pepper;

        public AuthService(ApplicationDbContext context, 
                          ILogger<AuthService> logger, 
                          IOptions<JwtSettings> jwtSettings,
                          AuditService auditService,
                          IConfiguration configuration)
        {
            _context = context;
            _logger = logger;
            _jwtSettings = jwtSettings.Value;
            _auditService = auditService;
            
            // Get the pepper from configuration (should be in environment variables in production)
            _pepper = configuration["PasswordSecurity:Pepper"] ?? 
                     throw new ArgumentNullException("Pepper must be configured");
        }

        public async Task<AuthResponse?> LoginAsync(LoginModel model, string? ipAddress = null, string? userAgent = null)
        {
            try
            {
                var user = await _context.Users
                    .SingleOrDefaultAsync(u => u.Username.ToLower() == model.Username.ToLower());

                if (user == null)
                {
                    await _auditService.LogAsync(Guid.NewGuid().ToString(), "AUTH_FAILED", 
                        $"Login failed for username: {model.Username} - User not found", ipAddress, userAgent);
                    return null;
                }

                // Verify the password using Argon2 with salt and pepper
                if (!VerifyPasswordHash(model.Password, user.PasswordHash, user.PasswordSalt))
                {
                    await _auditService.LogAsync(Guid.NewGuid().ToString(), "AUTH_FAILED", 
                        $"Login failed for username: {model.Username} - Invalid password", ipAddress, userAgent);
                    return null;
                }

                // Update last login time
                user.LastLogin = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                // Generate JWT token
                var token = GenerateJwtToken(user);
                
                await _auditService.LogAsync(Guid.NewGuid().ToString(), "AUTH_SUCCESS", 
                    $"User {user.Username} logged in successfully", ipAddress, userAgent);

                return new AuthResponse
                {
                    Token = token,
                    Username = user.Username,
                    Role = user.Role ?? "Admin",
                    Expiration = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for user {Username}", model.Username);
                return null;
            }
        }

        public async Task<AuthResponse?> RegisterAsync(RegisterModel model, string? ipAddress = null, string? userAgent = null)
        {
            try
            {
                // Check if user already exists
                if (await _context.Users.AnyAsync(u => u.Username.ToLower() == model.Username.ToLower()))
                {
                    return null;
                }

                // Create password hash and salt using Argon2
                CreatePasswordHash(model.Password, out byte[] passwordHash, out byte[] passwordSalt);

                // Create new user
                var user = new User
                {
                    Username = model.Username,
                    PasswordHash = passwordHash,
                    PasswordSalt = passwordSalt,
                    Role = "Admin", // Default role
                    CreatedAt = DateTime.UtcNow
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                // Generate JWT token
                var token = GenerateJwtToken(user);
                
                await _auditService.LogAsync(Guid.NewGuid().ToString(), "REGISTER_SUCCESS", 
                    $"New user {user.Username} registered", ipAddress, userAgent);

                return new AuthResponse
                {
                    Token = token,
                    Username = user.Username,
                    Role = user.Role ?? "Admin",
                    Expiration = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration for user {Username}", model.Username);
                return null;
            }
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            // Generate a random salt
            passwordSalt = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(passwordSalt);
            }

            // Combine password with pepper before hashing
            string pepperedPassword = password + _pepper;
            
            // Use Argon2id for password hashing (more secure than bcrypt or PBKDF2)
            using (var argon2 = new Argon2id(Encoding.UTF8.GetBytes(pepperedPassword)))
            {
                // Set recommended parameters for Argon2
                argon2.Salt = passwordSalt;
                argon2.DegreeOfParallelism = 8; // Number of cores
                argon2.MemorySize = 65536;     // 64 MB
                argon2.Iterations = 4;         // Number of passes
                
                passwordHash = argon2.GetBytes(32);
            }
        }

        private bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            // Combine password with pepper
            string pepperedPassword = password + _pepper;
            
            // Use Argon2id with the same parameters as during creation
            using (var argon2 = new Argon2id(Encoding.UTF8.GetBytes(pepperedPassword)))
            {
                argon2.Salt = storedSalt;
                argon2.DegreeOfParallelism = 8;
                argon2.MemorySize = 65536;
                argon2.Iterations = 4;
                
                var computedHash = argon2.GetBytes(32);
                
                // Compare computed hash with stored hash
                return computedHash.SequenceEqual(storedHash);
            }
        }

        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSettings.Secret);
            
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };
            
            // Add role claim if available
            if (!string.IsNullOrEmpty(user.Role))
            {
                claims.Add(new Claim(ClaimTypes.Role, user.Role));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
