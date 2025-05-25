using System.Text.RegularExpressions;
using System.IO.Compression;
using FakeAiChecker.Models;
using FakeAiChecker.Data;

namespace FakeAiChecker.Services
{
    public class SecretScannerService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<SecretScannerService> _logger;
        private readonly AuditService _auditService;

        // Regex patterns for common secrets
        private readonly Dictionary<string, Regex> _secretPatterns = new()
        {
            { "AWS_ACCESS_KEY", new Regex(@"AKIA[0-9A-Z]{16}", RegexOptions.IgnoreCase) },
            { "AWS_SECRET_KEY", new Regex(@"[0-9a-zA-Z/+]{40}", RegexOptions.IgnoreCase) },
            { "GITHUB_TOKEN", new Regex(@"ghp_[a-zA-Z0-9]{36}", RegexOptions.IgnoreCase) },
            { "SLACK_TOKEN", new Regex(@"xox[baprs]-([0-9a-zA-Z]{10,48})", RegexOptions.IgnoreCase) },
            { "DISCORD_TOKEN", new Regex(@"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}", RegexOptions.IgnoreCase) },
            { "GOOGLE_API_KEY", new Regex(@"AIza[0-9A-Za-z\-_]{35}", RegexOptions.IgnoreCase) },
            { "FIREBASE_KEY", new Regex(@"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", RegexOptions.IgnoreCase) },
            { "STRIPE_KEY", new Regex(@"sk_(test|live)_[0-9a-zA-Z]{24}", RegexOptions.IgnoreCase) },
            { "TWILIO_SID", new Regex(@"AC[a-zA-Z0-9_-]{32}", RegexOptions.IgnoreCase) },
            { "GENERIC_API_KEY", new Regex(@"['""]?[a-zA-Z0-9_-]*api[_-]?key['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_-]{20,}['""]?", RegexOptions.IgnoreCase) },
            { "GENERIC_SECRET", new Regex(@"['""]?[a-zA-Z0-9_-]*secret['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_-]{20,}['""]?", RegexOptions.IgnoreCase) },
            { "GENERIC_TOKEN", new Regex(@"['""]?[a-zA-Z0-9_-]*token['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_-]{20,}['""]?", RegexOptions.IgnoreCase) },
            { "GENERIC_PASSWORD", new Regex(@"['""]?password['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_@#$%^&*-]{8,}['""]?", RegexOptions.IgnoreCase) },
            { "DATABASE_URL", new Regex(@"['""]?database[_-]?url['""]?\s*[:=]\s*['""]?[a-zA-Z0-9+]+://[^\s'""]+", RegexOptions.IgnoreCase) },
            { "PRIVATE_KEY", new Regex(@"-----BEGIN (RSA )?PRIVATE KEY-----", RegexOptions.IgnoreCase) }
        };

        // Suspicious file extensions and names
        private readonly HashSet<string> _suspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".env", ".environment", ".config", ".conf", ".ini", ".properties", ".yaml", ".yml", ".json", ".xml"
        };

        private readonly HashSet<string> _suspiciousFileNames = new(StringComparer.OrdinalIgnoreCase)
        {
            ".env", ".env.local", ".env.production", ".env.development", "config.json", "secrets.json",
            "credentials.json", "settings.json", "app.config", "web.config", "database.yml", "secrets.yml"
        };

        public SecretScannerService(ApplicationDbContext context, ILogger<SecretScannerService> logger, AuditService auditService)
        {
            _context = context;
            _logger = logger;
            _auditService = auditService;
        }

        public async Task<ScanResultViewModel> ScanFileAsync(IFormFile file, string sessionId, string userIpAddress, string userAgent)
        {
            var startTime = DateTime.UtcNow;
            var tempPath = Path.GetTempPath();
            var sessionFolder = Path.Combine(tempPath, $"scan_{sessionId}");
            
            try
            {
                // Create secure temporary directory
                Directory.CreateDirectory(sessionFolder);
                
                await _auditService.LogAsync(sessionId, "SCAN_STARTED", $"File: {file.FileName}, Size: {file.Length}", userIpAddress, userAgent);

                // Validate file size (max 50MB)
                if (file.Length > 50 * 1024 * 1024)
                {
                    throw new InvalidOperationException("File size exceeds 50MB limit");
                }

                var filePath = Path.Combine(sessionFolder, file.FileName);
                
                // Save uploaded file
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                var scanResult = new ScanResult
                {
                    SessionId = sessionId,
                    FileName = file.FileName,
                    FilePath = filePath,
                    ScanDate = DateTime.UtcNow,
                    FakeAiPercentage = GenerateRandomPercentage(),
                    UserIpAddress = userIpAddress,
                    UserAgent = userAgent
                };
                scanResult.HumanPercentage = 100 - scanResult.FakeAiPercentage;

                _context.ScanResults.Add(scanResult);
                await _context.SaveChangesAsync();

                var secrets = new List<string>();

                // Scan the file/archive
                if (IsArchiveFile(file.FileName))
                {
                    secrets = await ScanArchiveAsync(filePath, scanResult.Id, sessionId);
                }
                else
                {
                    secrets = await ScanSingleFileAsync(filePath, scanResult.Id, sessionId);
                }

                await _auditService.LogAsync(sessionId, "SCAN_COMPLETED", $"Found {secrets.Count} secrets", userIpAddress, userAgent);

                return new ScanResultViewModel
                {
                    SessionId = sessionId,
                    FileName = file.FileName,
                    AiPercentage = scanResult.FakeAiPercentage,
                    HumanPercentage = scanResult.HumanPercentage,
                    FoundSecrets = secrets,
                    ScanDate = scanResult.ScanDate,
                    ProcessingTime = DateTime.UtcNow - startTime
                };
            }
            finally
            {
                // Clean up temporary files
                if (Directory.Exists(sessionFolder))
                {
                    try
                    {
                        Directory.Delete(sessionFolder, true);
                        await _auditService.LogAsync(sessionId, "CLEANUP_COMPLETED", "Temporary files deleted", userIpAddress, userAgent);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to clean up temporary files for session {SessionId}", sessionId);
                    }
                }
            }
        }

        private async Task<List<string>> ScanArchiveAsync(string archivePath, int scanResultId, string sessionId)
        {
            var secrets = new List<string>();
            var extractPath = Path.Combine(Path.GetDirectoryName(archivePath)!, "extracted");
            
            try
            {
                Directory.CreateDirectory(extractPath);

                // Extract ZIP archive using System.IO.Compression
                if (Path.GetExtension(archivePath).ToLowerInvariant() == ".zip")
                {
                    using (var archive = ZipFile.OpenRead(archivePath))
                    {
                        foreach (var entry in archive.Entries)
                        {
                            // Security check: prevent path traversal
                            if (entry.FullName.Contains("..") || Path.IsPathRooted(entry.FullName))
                            {
                                _logger.LogWarning("Suspicious file path detected: {FileName}", entry.FullName);
                                continue;
                            }

                            var entryPath = Path.Combine(extractPath, entry.FullName);
                            var entryDir = Path.GetDirectoryName(entryPath);
                            
                            if (!string.IsNullOrEmpty(entryDir))
                            {
                                Directory.CreateDirectory(entryDir);
                            }

                            if (!string.IsNullOrEmpty(entry.Name))
                            {
                                entry.ExtractToFile(entryPath, true);
                                var fileSecrets = await ScanSingleFileAsync(entryPath, scanResultId, sessionId);
                                secrets.AddRange(fileSecrets);
                            }
                        }
                    }
                }
                else
                {
                    // For other archive types, just scan the archive file itself
                    var fileSecrets = await ScanSingleFileAsync(archivePath, scanResultId, sessionId);
                    secrets.AddRange(fileSecrets);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting archive for session {SessionId}", sessionId);
            }

            return secrets;
        }

        private async Task<List<string>> ScanSingleFileAsync(string filePath, int scanResultId, string sessionId)
        {
            var secrets = new List<string>();
            
            try
            {
                var fileName = Path.GetFileName(filePath);
                var fileExtension = Path.GetExtension(filePath);

                // Check if file is suspicious by name or extension
                if (_suspiciousFileNames.Contains(fileName) || _suspiciousExtensions.Contains(fileExtension))
                {
                    secrets.Add($"Suspicious file detected: {fileName}");
                }

                // Read file content (with size limit)
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 10 * 1024 * 1024) // Skip files larger than 10MB
                {
                    return secrets;
                }

                var content = await File.ReadAllTextAsync(filePath);

                // Scan for secrets using regex patterns
                foreach (var pattern in _secretPatterns)
                {
                    var matches = pattern.Value.Matches(content);
                    foreach (Match match in matches)
                    {                        var secretFinding = new SecretFinding
                        {
                            ScanResultId = scanResultId,
                            SecretType = pattern.Key,
                            FileName = fileName,
                            FilePath = filePath,
                            SecretValue = match.Value, // No masking - show the actual secret
                            Context = GetContext(content, match.Index, 50),
                            FoundAt = DateTime.UtcNow
                        };                        _context.SecretFindings.Add(secretFinding);
                        secrets.Add($"{pattern.Key} found in {fileName}: {match.Value}");
                    }
                }

                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning file {FilePath} for session {SessionId}", filePath, sessionId);
            }

            return secrets;
        }

        private static string MaskSecret(string secret)
        {
            if (secret.Length <= 6)
                return "***";
            
            return secret[..3] + new string('*', secret.Length - 6) + secret[^3..];
        }

        private static string GetContext(string content, int index, int contextLength)
        {
            var start = Math.Max(0, index - contextLength);
            var end = Math.Min(content.Length, index + contextLength);
            return content[start..end].Replace("\n", " ").Replace("\r", " ");
        }

        private static bool IsArchiveFile(string fileName)
        {
            var extension = Path.GetExtension(fileName).ToLowerInvariant();
            return extension is ".zip" or ".rar" or ".7z" or ".tar" or ".gz";
        }

        private static int GenerateRandomPercentage()
        {
            var random = new Random();
            return random.Next(15, 86); // Random between 15% and 85%
        }
    }
}
