
namespace FakeAiChecker.Middleware
{
    public class JwtCookieMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtCookieMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Check if there's a JWT cookie and no Authorization header
            if (context.Request.Cookies.TryGetValue("JwtToken", out string? token) &&
                !context.Request.Headers.ContainsKey("Authorization"))
            {
                // Add Authorization header with the Bearer token
                context.Request.Headers.Authorization = $"Bearer {token}";
            }

            await _next(context);
        }
    }

    // Extension method
    public static class JwtCookieMiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtCookieMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<JwtCookieMiddleware>();
        }
    }
}
