using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FakeAiChecker.Data;
using FakeAiChecker.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using FakeAiChecker.Services;

namespace FakeAiChecker.Controllers
{
    [Authorize(Roles = "Admin", AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class AdminController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AdminController> _logger;
        private readonly AuthService _authService;

        public AdminController(ApplicationDbContext context, ILogger<AdminController> logger, AuthService authService)
        {
            _context = context;
            _logger = logger;
            _authService = authService;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return RedirectToAction("SecurityFindings");
        }

        // Simple admin interface to view security findings
        [HttpGet]
        public async Task<IActionResult> SecurityFindings()
        {
            // If not authenticated, redirect to login
            if (!User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Login", "Auth");
            }

            var findings = await _context.SecretFindings
                .Include(s => s.ScanResult)
                .OrderByDescending(s => s.FoundAt)
                .Take(50) // Show last 50 findings
                .ToListAsync();

            return View(findings);
        }

        // View all scan results
        [HttpGet]
        public async Task<IActionResult> ScanResults()
        {
            // If not authenticated, redirect to login
            if (!User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Login", "Auth");
            }

            var results = await _context.ScanResults
                .Include(s => s.SecretFindings)
                .OrderByDescending(s => s.ScanDate)
                .Take(50) // Show last 50 scans
                .ToListAsync();

            return View(results);
        }

        // View audit logs
        [HttpGet]
        public async Task<IActionResult> AuditLogs()
        {
            // If not authenticated, redirect to login
            if (!User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Login", "Auth");
            }

            var logs = await _context.AuditLogs
                .OrderByDescending(a => a.Timestamp)
                .Take(100) // Show last 100 audit logs
                .ToListAsync();

            return View(logs);
        }

        // Change password functionality
        [HttpGet]
        public IActionResult ChangePassword()
        {
            // If not authenticated, redirect to login
            if (!User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Login", "Auth");
            }

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
        {
            // If not authenticated, redirect to login
            if (!User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Login", "Auth");
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }            var username = User.Identity?.Name;
            if (string.IsNullOrEmpty(username))
            {
                ViewBag.ErrorMessage = "Unable to determine current user";
                return View(model);
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var success = await _authService.ChangePasswordAsync(username, model, ipAddress, userAgent);

            if (success)
            {
                ViewBag.SuccessMessage = "Password changed successfully";
                ModelState.Clear();
                return View(new ChangePasswordModel());
            }
            else
            {
                ViewBag.ErrorMessage = "Failed to change password. Please check your current password and try again.";
                return View(model);
            }
        }
    }
}
