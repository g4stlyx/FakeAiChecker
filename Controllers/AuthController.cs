using Microsoft.AspNetCore.Mvc;
using FakeAiChecker.Models;
using FakeAiChecker.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace FakeAiChecker.Controllers
{
    public class AuthController : Controller
    {
        private readonly AuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(AuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }
        [HttpGet]
        public IActionResult Login()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("SecurityFindings", "Admin");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            
            var response = await _authService.LoginAsync(model, ipAddress, userAgent);
            
            if (response == null)
            {
                ViewBag.ErrorMessage = "Invalid username or password";
                return View(model);
            }

            // Store token in session
            HttpContext.Response.Cookies.Append("JwtToken", response.Token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = response.Expiration
            });

            return RedirectToAction("SecurityFindings", "Admin");
        }

        [HttpGet]
        public IActionResult Logout()
        {
            // Clear the JWT cookie
            HttpContext.Response.Cookies.Delete("JwtToken");
            
            return RedirectToAction("Index", "Home");
        }
        
        [HttpGet]
        [Authorize(Roles = "Admin", AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin", AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            
            var response = await _authService.RegisterAsync(model, ipAddress, userAgent);
            
            if (response == null)
            {
                ViewBag.ErrorMessage = "User already exists or registration failed";
                return View(model);
            }

            ViewBag.SuccessMessage = $"Admin user '{model.Username}' created successfully";
            ModelState.Clear();
            return View(new RegisterModel());
        }        // API endpoints

        [Route("api/[controller]/login")]
        [HttpPost]
        [ApiExplorerSettings(IgnoreApi = false)]
        public async Task<IActionResult> ApiLogin([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            
            var response = await _authService.LoginAsync(model, ipAddress, userAgent);
            
            if (response == null)
            {
                return Unauthorized(new { Message = "Invalid username or password" });
            }

            return Ok(response);
        }

        [Route("api/[controller]/register")]
        [HttpPost]
        [Authorize(Roles = "Admin", AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [ApiExplorerSettings(IgnoreApi = false)]
        public async Task<IActionResult> ApiRegister([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            
            var response = await _authService.RegisterAsync(model, ipAddress, userAgent);
            
            if (response == null)
            {
                return BadRequest(new { Message = "User already exists or registration failed" });
            }

            return Ok(response);
        }

        [Route("api/[controller]/validate")]
        [HttpGet]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [ApiExplorerSettings(IgnoreApi = false)]
        public IActionResult ValidateToken()
        {
            return Ok(new { IsValid = true, Username = User.Identity?.Name });
        }
    }
}
