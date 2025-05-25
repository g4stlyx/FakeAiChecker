using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using FakeAiChecker.Models;

namespace FakeAiChecker.Auth
{
    public class JwtCookieAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly JwtSettings _jwtSettings;

        public JwtCookieAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
#pragma warning disable CS0618 // Type or member is obsolete
            ISystemClock clock,
#pragma warning restore CS0618 // Type or member is obsolete
            IOptions<JwtSettings> jwtSettings) 
#pragma warning disable CS0618 // Type or member is obsolete
            : base(options, logger, encoder, clock)
#pragma warning restore CS0618 // Type or member is obsolete
        {
            _jwtSettings = jwtSettings.Value;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // Check if token exists in the cookie
            if (!Request.Cookies.TryGetValue("JwtToken", out string? token))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            try
            {
                // Validate the token
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_jwtSettings.Secret);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _jwtSettings.Issuer,
                    ValidAudience = _jwtSettings.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ClockSkew = TimeSpan.Zero
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

                // Create authentication ticket
                var ticket = new AuthenticationTicket(principal, Scheme.Name);
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }
            catch (Exception ex)
            {
                // If validation fails, clear the cookie
                Response.Cookies.Delete("JwtToken");
                return Task.FromResult(AuthenticateResult.Fail($"Authentication failed: {ex.Message}"));
            }
        }
    }
}
