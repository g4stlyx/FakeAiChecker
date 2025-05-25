using System.Security.Cryptography;
using System.Text;

namespace FakeAiChecker.Services
{
    public class SecurityService
    {
        private readonly ILogger<SecurityService> _logger;
        private readonly IConfiguration _configuration;

        public SecurityService(ILogger<SecurityService> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public bool IsFileTypeAllowed(string fileName)
        {
            var allowedExtensions = _configuration.GetSection("Security:AllowedFileExtensions").Get<string[]>();
            var extension = Path.GetExtension(fileName).ToLowerInvariant();
            
            return allowedExtensions?.Contains(extension) == true;
        }

        public bool IsFileSizeAllowed(long fileSize)
        {
            var maxSizeMB = _configuration.GetValue<int>("Security:MaxUploadSizeMB", 50);
            var maxSizeBytes = maxSizeMB * 1024 * 1024;
            
            return fileSize <= maxSizeBytes;
        }

        public string GenerateSecureSessionId()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        }

        public string HashSensitiveData(string data)
        {
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
            return Convert.ToBase64String(hashBytes);
        }

        public bool ValidateFileName(string fileName)
        {
            // Check for path traversal attempts
            if (fileName.Contains("..") || fileName.Contains("/") || fileName.Contains("\\"))
            {
                _logger.LogWarning("Suspicious file name detected: {FileName}", fileName);
                return false;
            }

            // Check for null bytes or control characters
            if (fileName.Any(c => char.IsControl(c) && c != '\t'))
            {
                _logger.LogWarning("File name contains control characters: {FileName}", fileName);
                return false;
            }

            return true;
        }

        public void LogSecurityEvent(string eventType, string details, string? userIpAddress = null)
        {
            _logger.LogWarning("Security Event - Type: {EventType}, Details: {Details}, IP: {IP}", 
                eventType, details, userIpAddress ?? "Unknown");
        }
    }
}
