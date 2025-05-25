using FakeAiChecker.Data;
using FakeAiChecker.Models;

namespace FakeAiChecker.Services
{
    public class AuditService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AuditService> _logger;

        public AuditService(ApplicationDbContext context, ILogger<AuditService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task LogAsync(string sessionId, string action, string details, string? userIpAddress = null, string? userAgent = null)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    SessionId = sessionId,
                    Action = action,
                    Details = details,
                    Timestamp = DateTime.UtcNow,
                    UserIpAddress = userIpAddress,
                    UserAgent = userAgent
                };

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Audit log created: {Action} for session {SessionId}", action, sessionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create audit log for session {SessionId}", sessionId);
            }
        }
    }
}
