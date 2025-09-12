using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace IdentityService.Jwt.Identity;

// Source: https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/BearerToken/src/BearerTokenHandler.cs
// Source: https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/JwtBearer/src/JwtBearerHandler.cs

public class JwtTokenHandler : JwtBearerHandler, IAuthenticationSignInHandler
{
    private ITokenService _tokenService => Context.RequestServices.GetRequiredService<JwtTokenService>();

    public JwtTokenHandler(
        IOptionsMonitor<JwtBearerOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder)
    {

    }

    public virtual Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        // ForwardSignIn is used to forward the sign-in request to another authentication handler.
        var target = ResolveTarget(Options.ForwardSignIn);

        // If a target is not specified, we handle the sign-in ourselves with JWT.
        return (target != null)
            ? Context.SignInAsync(target, user, properties)
            : HandleSignInAsync(user, properties);
    }

    public Task SignOutAsync(AuthenticationProperties? properties)
    {
        var target = ResolveTarget(Options.ForwardSignOut);

        return (target != null)
            ? Context.SignOutAsync(target, properties)
            : HandleSignOutAsync(properties ?? new AuthenticationProperties());
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.Append(HeaderNames.WWWAuthenticate, "Bearer");
        return base.HandleChallengeAsync(properties);
    }

    protected virtual async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        var utcNow = DateTime.UtcNow;

        var result = await _tokenService.CreateTokenAsync(user.FindFirstValue(ClaimTypes.NameIdentifier)!, user);

        if (result.IsFailed)
        {
            Logger.LogError("Failed to create user token: {Errors}", result.Errors);
            Context.Response.StatusCode = StatusCodes.Status500InternalServerError;

            var tokenProblemDetails = new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "Sign-In Failed",
                Detail = "An error occurred while creating the token.",
            };

            await Context.Response.WriteAsJsonAsync(tokenProblemDetails);
        }
        else
        {
            await Context.Response.WriteAsJsonAsync(result.Value, new JsonSerializerOptions
            {
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            });
        }
    }

    protected virtual async Task HandleSignOutAsync(AuthenticationProperties properties)
    {
        // Try to get the refresh token from the request header;
        var refreshToken = Context.Request.Headers["X-Refresh-Token"].FirstOrDefault();
        if (string.IsNullOrEmpty(refreshToken))
        {
            // Error out if no refresh token is provided;
            Context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        // Revoke tokens if needed; Requires Refresh token to invalidate
        var result = await _tokenService.RevokeTokenAsync(refreshToken!);
        if (result.IsFailed)
        {
            Context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            return;
        }
    }
}
