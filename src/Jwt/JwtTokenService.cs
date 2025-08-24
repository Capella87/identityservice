using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FluentResults;
using IdentityService;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace IdentityService.Jwt;

public class JwtTokenService : ITokenService
{
    private readonly IConfiguration _config;
    private readonly ILogger<JwtTokenService> _logger;
    private readonly JsonWebTokenHandler _jwtHandler;

    ILogger<ITokenService> ITokenService.Logger => _logger;

    public JwtTokenService(IConfiguration config, ILogger<JwtTokenService> logger)
    {
        _config = config;
        _logger = logger;
        _jwtHandler = new JsonWebTokenHandler();
    }

    public virtual async Task<Result<ITokenResponse?>> CreateTokenAsync(string userId, ClaimsPrincipal user)
    {
        if ((_config.GetValue<bool?>("JwtSettings:RefreshToken:IsEnabled") ?? false))
        {
            // Issue refresh token

            // Register to database
        }

        // Issue access token
        var issuedAt = DateTimeOffset.UtcNow;
        var result = await GenerateAccessTokenAsync(user.Claims,
            issuedAt,
            issuedAt.AddMinutes(
                _config.GetValue<long?>("JwtSettings:AccessToken:ExpiresInMinutes") ?? 15),
            issuedAt);
        if (result.IsFailed)
        {
            return Result.Fail(result.Errors);
        }

        return Result.Ok<ITokenResponse?>(new JwtTokenResponse
        {
            AccessToken = (result.Value as JsonWebToken)!.EncodedToken,
            AccessTokenExpiresAt = result.Value.ValidTo,
            RefreshToken = null,
            RefreshTokenExpiresAt = null
        });
    }

    public virtual async Task<Result<SecurityToken>> GenerateAccessTokenAsync(IEnumerable<Claim> claims,
        DateTimeOffset? issuedAt,
        DateTimeOffset? expiredAt,
        DateTimeOffset? notBefore)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Generate a new refresh token. Remember that you must set times
    /// </summary>
    /// <param name="issuedAt"></param>
    /// <param name="expiredAt"></param>
    /// <param name="notBefore"></param>
    /// <returns></returns>
    public virtual async Task<Result<IToken?>> GenerateRefreshTokenAsync(DateTimeOffset? issuedAt = null)
    {
        var arr = new byte[32];
        var rng = RandomNumberGenerator.Create();
        rng.GetBytes(arr);

        // TODO: Decide whether to separate the logic of setting times...
        // Re-issuing refresh token requires to revoke the old one... It may take some time.
        if (issuedAt == null)
        {
            issuedAt = DateTimeOffset.UtcNow;
        }
        return Result.Ok<IToken?>(new JwtRefreshToken
        {
            Token = Convert.ToBase64String(arr),
            IssuedAt = issuedAt,
        });
    }

    public virtual async Task<Result<IToken?>> GetTokenAsync(string token)
    {
        throw new NotImplementedException();
    }

    public Task<Result<ITokenResponse?>> RefreshTokenAsync(string refreshToken)
    {
        throw new NotImplementedException();
    }

    public virtual async Task<Result> RevokeAllUserTokensAsync(string userId)
    {
        throw new NotImplementedException();
    }

    public virtual async Task<Result> RevokeTokenAsync(string token)
    {
        throw new NotImplementedException();
    }
}
