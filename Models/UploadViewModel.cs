using System.ComponentModel.DataAnnotations;

namespace FakeAiChecker.Models
{
    public class UploadViewModel
    {
        [Required(ErrorMessage = "Please select a file to upload")]
        public IFormFile? File { get; set; }
    }

    public class ScanResultViewModel
    {
        public string SessionId { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public int AiPercentage { get; set; }
        public int HumanPercentage { get; set; }
        public List<string> FoundSecrets { get; set; } = new();
        public DateTime ScanDate { get; set; }
        public TimeSpan ProcessingTime { get; set; }
    }
}
