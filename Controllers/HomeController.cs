using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using FakeAiChecker.Models;
using FakeAiChecker.Services;

namespace FakeAiChecker.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly SecretScannerService _scannerService;
    private readonly AuditService _auditService;
    private readonly SecurityService _securityService;

    public HomeController(ILogger<HomeController> logger, SecretScannerService scannerService, 
        AuditService auditService, SecurityService securityService)
    {
        _logger = logger;
        _scannerService = scannerService;
        _auditService = auditService;
        _securityService = securityService;
    }

    public IActionResult Index()
    {
        return View(new UploadViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [RequestSizeLimit(50 * 1024 * 1024)] // 50MB limit
    public async Task<IActionResult> Upload(UploadViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View("Index", model);
        }

        if (model.File == null)
        {
            ModelState.AddModelError("File", "Please select a file to upload");
            return View("Index", model);
        }

        var userIpAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var userAgent = Request.Headers.UserAgent.ToString();

        try
        {
            // Security validations
            if (!_securityService.ValidateFileName(model.File.FileName))
            {
                _securityService.LogSecurityEvent("INVALID_FILENAME", model.File.FileName, userIpAddress);
                ModelState.AddModelError("File", "Invalid file name detected");
                return View("Index", model);
            }

            if (!_securityService.IsFileTypeAllowed(model.File.FileName))
            {
                _securityService.LogSecurityEvent("DISALLOWED_FILE_TYPE", model.File.FileName, userIpAddress);
                ModelState.AddModelError("File", "File type not allowed");
                return View("Index", model);
            }

            if (!_securityService.IsFileSizeAllowed(model.File.Length))
            {
                _securityService.LogSecurityEvent("FILE_SIZE_EXCEEDED", $"{model.File.FileName} - {model.File.Length} bytes", userIpAddress);
                ModelState.AddModelError("File", "File size exceeds the allowed limit");
                return View("Index", model);
            }

            var sessionId = _securityService.GenerateSecureSessionId();

            await _auditService.LogAsync(sessionId, "UPLOAD_STARTED", $"File: {model.File.FileName}", userIpAddress, userAgent);

            var result = await _scannerService.ScanFileAsync(model.File, sessionId, userIpAddress!, userAgent);
            
            return View("Result", result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing upload for file {FileName}", model.File.FileName);
            _securityService.LogSecurityEvent("PROCESSING_ERROR", $"{model.File.FileName} - {ex.Message}", userIpAddress);
            ModelState.AddModelError("", "An error occurred while processing your file. Please try again.");
            return View("Index", model);
        }
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
