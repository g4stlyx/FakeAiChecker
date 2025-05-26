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
            { "GITHUB_OAUTH_TOKEN", new Regex(@"gho_[a-zA-Z0-9]{36}", RegexOptions.IgnoreCase) },
            { "GITHUB_APP_TOKEN", new Regex(@"ghu_[a-zA-Z0-9]{36}", RegexOptions.IgnoreCase) },
            { "GITHUB_REFRESH_TOKEN", new Regex(@"ghr_[a-zA-Z0-9]{76}", RegexOptions.IgnoreCase) },
            { "SLACK_TOKEN", new Regex(@"xox[baprs]-([0-9a-zA-Z]{10,48})", RegexOptions.IgnoreCase) },
            { "DISCORD_TOKEN", new Regex(@"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}", RegexOptions.IgnoreCase) },
            { "GOOGLE_API_KEY", new Regex(@"AIza[0-9A-Za-z\-_]{35}", RegexOptions.IgnoreCase) },
            { "FIREBASE_KEY", new Regex(@"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", RegexOptions.IgnoreCase) },
            { "STRIPE_KEY", new Regex(@"sk_(test|live)_[0-9a-zA-Z]{24}", RegexOptions.IgnoreCase) },
            { "STRIPE_PUBLISHABLE_KEY", new Regex(@"pk_(test|live)_[0-9a-zA-Z]{24}", RegexOptions.IgnoreCase) },
            { "TWILIO_SID", new Regex(@"AC[a-zA-Z0-9_-]{32}", RegexOptions.IgnoreCase) },
            { "TWILIO_AUTH_TOKEN", new Regex(@"SK[0-9a-fA-F]{32}", RegexOptions.IgnoreCase) },
            { "SENDGRID_API_KEY", new Regex(@"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", RegexOptions.IgnoreCase) },
            { "MAILCHIMP_API_KEY", new Regex(@"[0-9a-f]{32}-us[0-9]{1,2}", RegexOptions.IgnoreCase) },
            { "MAILGUN_API_KEY", new Regex(@"key-[0-9a-zA-Z]{32}", RegexOptions.IgnoreCase) },
            { "JWT_TOKEN", new Regex(@"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", RegexOptions.IgnoreCase) },
            { "HEROKU_API_KEY", new Regex(@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", RegexOptions.IgnoreCase) },
            { "AZURE_CONNECTION_STRING", new Regex(@"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net", RegexOptions.IgnoreCase) },
            { "AZURE_SQL_CONNECTION", new Regex(@"Server=tcp:[^,]+,1433;Initial Catalog=[^;]+;Persist Security Info=False;User ID=[^;]+;Password=[^;]+;MultipleActiveResultSets=False;Encrypt=True", RegexOptions.IgnoreCase) },
            { "OPENAI_API_KEY", new Regex(@"sk-[a-zA-Z0-9]{48}", RegexOptions.IgnoreCase) },
            { "FACEBOOK_ACCESS_TOKEN", new Regex(@"EAA[a-zA-Z0-9]{20,}", RegexOptions.IgnoreCase) },
            { "TWITTER_ACCESS_TOKEN", new Regex(@"[0-9]{10,}-[0-9A-Za-z]{40,}", RegexOptions.IgnoreCase) },
            { "SQUARE_ACCESS_TOKEN", new Regex(@"sq0atp-[0-9A-Za-z-_]{22}", RegexOptions.IgnoreCase) },
            { "SQUARE_OAUTH_SECRET", new Regex(@"sq0csp-[0-9A-Za-z-_]{43}", RegexOptions.IgnoreCase) },
            { "PAYPAL_CLIENT_ID", new Regex(@"A[a-zA-Z0-9_-]{20}", RegexOptions.IgnoreCase) },
            { "PAYPAL_SECRET", new Regex(@"E[a-zA-Z0-9_-]{20}", RegexOptions.IgnoreCase) },
            { "GENERIC_API_KEY", new Regex(@"['""]?[a-zA-Z0-9_-]*api[_-]?key['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_\-\+\/]{16,}['""]?", RegexOptions.IgnoreCase) },
            { "GENERIC_SECRET", new Regex(@"['""]?[a-zA-Z0-9_-]*secret['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_\-\+\/]{16,}['""]?", RegexOptions.IgnoreCase) },
            { "GENERIC_TOKEN", new Regex(@"['""]?[a-zA-Z0-9_-]*token['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_\-\+\/]{16,}['""]?", RegexOptions.IgnoreCase) },
            { "GENERIC_KEY", new Regex(@"['""]?[a-zA-Z0-9_-]*key['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_\-\+\/]{20,}['""]?", RegexOptions.IgnoreCase) },
            { "GENERIC_ACCESS_TOKEN", new Regex(@"['""]?[a-zA-Z0-9_-]*access[_-]?token['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_\-\+\/]{20,}['""]?", RegexOptions.IgnoreCase) },
            { "GENERIC_AUTH_TOKEN", new Regex(@"['""]?[a-zA-Z0-9_-]*auth[_-]?token['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_\-\+\/]{20,}['""]?", RegexOptions.IgnoreCase) },
            { "BEARER_TOKEN", new Regex(@"Bearer\s+[a-zA-Z0-9_\-\+\/]{20,}", RegexOptions.IgnoreCase) },
            { "API_KEY_PATTERN", new Regex(@"\b[A-Za-z0-9_-]*API[_-]?KEY\b['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_\-\+\/]{16,}['""]?", RegexOptions.IgnoreCase) },
            { "TOKEN_PATTERN", new Regex(@"\b[A-Za-z0-9_-]*TOKEN\b['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_\-\+\/]{16,}['""]?", RegexOptions.IgnoreCase) },
            { "GENERIC_PASSWORD", new Regex(@"['""]?password['""]?\s*[:=]\s*['""]?[a-zA-Z0-9_@#$%^&*-]{8,}['""]?", RegexOptions.IgnoreCase) },
            { "DATABASE_URL", new Regex(@"['""]?database[_-]?url['""]?\s*[:=]\s*['""]?[a-zA-Z0-9+]+://[^\s'""]+", RegexOptions.IgnoreCase) },
            { "MONGODB_URI", new Regex(@"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+/[^?]+", RegexOptions.IgnoreCase) },
            { "POSTGRESQL_URI", new Regex(@"postgres://[^:]+:[^@]+@[^/]+/[^?]+", RegexOptions.IgnoreCase) },
            { "MYSQL_URI", new Regex(@"mysql://[^:]+:[^@]+@[^/]+/[^?]+", RegexOptions.IgnoreCase) },
            { "PRIVATE_KEY", new Regex(@"-----BEGIN (RSA )?PRIVATE KEY-----", RegexOptions.IgnoreCase) },
            { "SSH_PRIVATE_KEY", new Regex(@"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", RegexOptions.IgnoreCase) },
            { "PGP_PRIVATE_KEY", new Regex(@"-----BEGIN PGP PRIVATE KEY BLOCK-----", RegexOptions.IgnoreCase) },
            { "CERTIFICATE_WITH_PRIVATE_KEY", new Regex(@"-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----.*-----BEGIN PRIVATE KEY-----", RegexOptions.IgnoreCase | RegexOptions.Singleline) },
            { "NPM_TOKEN", new Regex(@"npm_[A-Za-z0-9]{36}", RegexOptions.IgnoreCase) },
            { "SHOPIFY_API_KEY", new Regex(@"shpat_[a-fA-F0-9]{32}", RegexOptions.IgnoreCase) },
            { "SHOPIFY_SHARED_SECRET", new Regex(@"shpss_[a-fA-F0-9]{32}", RegexOptions.IgnoreCase) },            
            { "DIGITALOCEAN_ACCESS_TOKEN", new Regex(@"dop_v1_[a-f0-9]{64}", RegexOptions.IgnoreCase) },
            { "GITLAB_TOKEN", new Regex(@"glpat-[0-9a-zA-Z\-]{20}", RegexOptions.IgnoreCase) },
            { "ASANA_TOKEN", new Regex(@"[0-9]{16}:[0-9a-f]{32}", RegexOptions.IgnoreCase) },
            { "BITBUCKET_CLIENT_ID", new Regex(@"[0-9a-zA-Z]{32}", RegexOptions.IgnoreCase) },
            { "BITBUCKET_CLIENT_SECRET", new Regex(@"[0-9a-zA-Z]{64}", RegexOptions.IgnoreCase) },
            { "DOCKERHUB_TOKEN", new Regex(@"dckr_pat_[a-zA-Z0-9_-]{64}", RegexOptions.IgnoreCase) },
            { "JIRA_TOKEN", new Regex(@"[a-zA-Z0-9]{24}", RegexOptions.IgnoreCase) },
            { "CONFLUENCE_TOKEN", new Regex(@"[a-zA-Z0-9]{24}", RegexOptions.IgnoreCase) },
            { "OKTA_API_TOKEN", new Regex(@"00[a-zA-Z0-9_-]{40}", RegexOptions.IgnoreCase) },
            { "CLOUDINARY_URL", new Regex(@"cloudinary://[0-9]{9}:[a-zA-Z0-9_-]{30}@[a-zA-Z0-9_-]+", RegexOptions.IgnoreCase) },
            { "BRAINTREE_TOKEN", new Regex(@"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", RegexOptions.IgnoreCase) },
            { "DROPBOX_ACCESS_TOKEN", new Regex(@"sl\.[a-zA-Z0-9_-]{136}", RegexOptions.IgnoreCase) },
            { "HUBSPOT_API_KEY", new Regex(@"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", RegexOptions.IgnoreCase) },
            { "MAPBOX_ACCESS_TOKEN", new Regex(@"pk\.[a-zA-Z0-9_-]{60,100}", RegexOptions.IgnoreCase) },
            { "LINEAR_API_KEY", new Regex(@"lin_api_[a-zA-Z0-9]{40,100}", RegexOptions.IgnoreCase) },
            { "TRELLO_API_KEY", new Regex(@"[0-9a-f]{32}", RegexOptions.IgnoreCase) },
            { "ALGOLIA_API_KEY", new Regex(@"[a-zA-Z0-9]{32}", RegexOptions.IgnoreCase) },
            { "AIRTABLE_API_KEY", new Regex(@"key[a-zA-Z0-9]{14}", RegexOptions.IgnoreCase) },
            { "NEW_RELIC_LICENSE_KEY", new Regex(@"[0-9a-f]{40}", RegexOptions.IgnoreCase) },
            { "DATADOG_API_KEY", new Regex(@"[0-9a-f]{32}", RegexOptions.IgnoreCase) },
            { "SENTRY_AUTH_TOKEN", new Regex(@"[0-9a-f]{64}", RegexOptions.IgnoreCase) },
            { "AMPLITUDE_API_KEY", new Regex(@"[0-9a-f]{32}", RegexOptions.IgnoreCase) },
            { "SEGMENT_API_KEY", new Regex(@"[a-zA-Z0-9]{64}", RegexOptions.IgnoreCase) },
            { "PUBNUB_PUBLISH_KEY", new Regex(@"pub-c-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", RegexOptions.IgnoreCase) },
            { "PUBNUB_SUBSCRIBE_KEY", new Regex(@"sub-c-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", RegexOptions.IgnoreCase) }
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
