using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;

namespace FakeAiChecker.Models
{
    public class ScanResult
    {
        [Key]
        public int Id { get; set; }
        public string SessionId { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public DateTime ScanDate { get; set; }
        public int FakeAiPercentage { get; set; }
        public int HumanPercentage { get; set; }
        public string? UserIpAddress { get; set; }
        public string? UserAgent { get; set; }

        // Navigation property
        public ICollection<SecretFinding> SecretFindings { get; set; } = new List<SecretFinding>();
    }

    public class SecretFinding
    {
        [Key]
        public int Id { get; set; }
        public int ScanResultId { get; set; }
        public string SecretType { get; set; } = string.Empty; // API_KEY, TOKEN, PASSWORD, etc.
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string SecretValue { get; set; } = string.Empty; // Masked for security
        public string Context { get; set; } = string.Empty; // Surrounding text
        public DateTime FoundAt { get; set; }
        
        public ScanResult ScanResult { get; set; } = null!;
    }

    public class AuditLog
    {
        [Key]
        public int Id { get; set; }
        public string SessionId { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string? UserIpAddress { get; set; }
        public string? UserAgent { get; set; }
    }
}
