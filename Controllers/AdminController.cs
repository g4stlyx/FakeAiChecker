using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FakeAiChecker.Data;
using FakeAiChecker.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace FakeAiChecker.Controllers
{
    [Authorize(Roles = "Admin", AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class AdminController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AdminController> _logger;

        public AdminController(ApplicationDbContext context, ILogger<AdminController> logger)
        {
            _context = context;
            _logger = logger;
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
    }
}
