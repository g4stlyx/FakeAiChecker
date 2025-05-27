using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using FakeAiChecker.Models;

namespace FakeAiChecker.Controllers
{
    public class ErrorController : Controller
    {
        private readonly ILogger<ErrorController> _logger;

        public ErrorController(ILogger<ErrorController> logger)
        {
            _logger = logger;
        }

        [Route("Error/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            var model = new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                StatusCode = statusCode
            };

            switch (statusCode)
            {
                case 404:
                    model.Title = "Page Not Found";
                    model.Message = "The page you are looking for could not be found.";
                    _logger.LogWarning("404 Error occurred. Request ID: {RequestId}, Path: {Path}", 
                        model.RequestId, HttpContext.Request.Path);
                    return View("Error404", model);

                case 401:
                    model.Title = "Authentication Required";
                    model.Message = "You need to log in to access this resource.";
                    _logger.LogWarning("401 Error occurred. Request ID: {RequestId}, Path: {Path}", 
                        model.RequestId, HttpContext.Request.Path);
                    return View("Error401", model);

                case 403:
                    model.Title = "Access Forbidden";
                    model.Message = "You don't have permission to access this resource.";
                    _logger.LogWarning("403 Error occurred. Request ID: {RequestId}, Path: {Path}", 
                        model.RequestId, HttpContext.Request.Path);
                    return View("Error401", model); // Use same view as 401

                case 500:
                    model.Title = "Internal Server Error";
                    model.Message = "Something went wrong on our end.";
                    _logger.LogError("500 Error occurred. Request ID: {RequestId}, Path: {Path}", 
                        model.RequestId, HttpContext.Request.Path);
                    return View("Error500", model);

                default:
                    model.Title = "Error";
                    model.Message = "An error occurred while processing your request.";
                    _logger.LogError("Unhandled status code {StatusCode}. Request ID: {RequestId}, Path: {Path}", 
                        statusCode, model.RequestId, HttpContext.Request.Path);
                    return View("Error", model);
            }
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Index()
        {
            var model = new ErrorViewModel 
            { 
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                StatusCode = 500,
                Title = "Internal Server Error",
                Message = "An unexpected error occurred."
            };

            _logger.LogError("General error occurred. Request ID: {RequestId}", model.RequestId);
            return View("Error500", model);
        }
    }
}
