using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FluentResults;
using IdentityService;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using FluentResults.Extensions;

namespace IdentityService.Jwt;

public class JwtTokenService : ITokenService
{
    private readonly IConfiguration _config;
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<JwtTokenService> _logger;
    private readonly JsonWebTokenHandler _jwtHandler;

    ILogger<ITokenService> ITokenService.Logger => _logger;

    public JwtTokenService(IConfiguration config, ILogger<JwtTokenService> logger, IOptions<JwtSettings> jwtSettings)
    {
        _config = config;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
        _jwtHandler = new JsonWebTokenHandler()
        {
            MapInboundClaims = JwtSecurityTokenHandler.DefaultMapInboundClaims,
        };
    }

    public virtual async Task<Result<ITokenResponse?>> CreateTokenAsync(string userId, ClaimsPrincipal user)
    {
        JwtRefreshToken? refreshToken = null;
        if ((_jwtSettings.RefreshToken?.EnableRefreshToken ?? false))
        {
            // Issue refresh token
            var current = DateTimeOffset.UtcNow;
            var tokenResult = await GenerateRefreshTokenAsync(current, current,
                current.AddMinutes(_jwtSettings.RefreshToken.ExpiresInMinutes ?? 10_080));

            if (tokenResult.IsFailed)
            {
                return Result.Fail("Failed to create a refresh token.");
            }
            refreshToken = tokenResult.Value as JwtRefreshToken;

            // Connect to the database and save the token.
        }

        // Issue access token
        var issuedAt = DateTimeOffset.UtcNow;
        var result = await GenerateAccessTokenAsync(user.Claims,
            issuedAt,
            issuedAt.AddMinutes(
                _jwtSettings.AccessToken.ExpiresInMinutes ?? 15),
            issuedAt);

        if (result.IsFailed)
        {
            return Result.Fail(result.Errors);
        }

        return Result.Ok<ITokenResponse?>(new JwtTokenResponse
        {
            AccessToken = (result.Value as JsonWebToken)!.EncodedToken,
            AccessTokenExpiresAt = result.Value.ValidTo,
            RefreshToken = refreshToken?.Token,
            RefreshTokenExpiresAt = refreshToken?.ExpiresAt,
        });
    }

    /// <summary>
    /// Generates a new JWT access token with the token descriptor.
    /// </summary>
    /// <param name="claims"></param>
    /// <param name="issuedAt"></param>
    /// <param name="expiresAt"></param>
    /// <param name="notBefore"></param>
    /// <returns></returns>
    public virtual async Task<Result<SecurityToken>> GenerateAccessTokenAsync(IEnumerable<Claim> claims,
        DateTimeOffset? issuedAt,
        DateTimeOffset? expiresAt,
        DateTimeOffset? notBefore)
    {
        var descriptor = GetAccessTokenDescriptor(claims);
        var encodedToken = _jwtHandler.CreateToken(descriptor);

        var token = _jwtHandler.ReadToken(encodedToken);
        return await Task.FromResult(Result.Ok(token));
    }

    /// <summary>
    /// Generate a new refresh token. Remember that you must set time to issue.
    /// </summary>
    /// <param name="issuedAt"></param>
    /// <param name="expiresAt"></param>
    /// <param name="notBefore"></param>
    /// <returns></returns>
    public virtual async Task<Result<IToken?>> GenerateRefreshTokenAsync(DateTimeOffset? issuedAt = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresAt = null)
    {
        var arr = new byte[32];
        var rng = RandomNumberGenerator.Create();
        rng.GetBytes(arr);

        // TODO: Decide whether to separate the logic of setting times...
        // Re-issuing refresh token requires to revoke the old one... It may take some time.
        issuedAt ??= DateTimeOffset.UtcNow;
        return await Task.FromResult(Result.Ok<IToken?>(new JwtRefreshToken
        {
            Token = Convert.ToBase64String(arr),
            IssuedAt = issuedAt,
            NotBefore = notBefore ?? issuedAt,
            ExpiresAt = expiresAt ?? issuedAt?.AddMinutes(_jwtSettings.RefreshToken.ExpiresInMinutes ?? 10_080)
        }));
    }

    public virtual async Task<Result<IToken?>> GetTokenAsync(string token)
    {
        throw new NotImplementedException();
    }

    public async Task<Result<ITokenResponse?>> RefreshTokenAsync(string refreshToken)
    {
        var rt = await GetTokenAsync(refreshToken);

        if (rt.IsFailed)
        {
            return Result.Fail("Refresh token is not found or expired.");
        }

        // Revoke the refresh token
        var revokeResult = await RevokeTokenAsync(rt.Value!.Token);

        if (revokeResult.Errors.Count > 0)
        {
            return Result.Fail(revokeResult.Errors);
        }

        var iat = DateTimeOffset.UtcNow;

        var rTokenResult = await GenerateRefreshTokenAsync(iat, iat, null);

        if (rTokenResult.IsFailed)
        {
            return Result.Fail(rTokenResult.Errors);
        }

        // Save to the database

        // Create an access token
    }

    public virtual async Task<Result> RevokeAllUserTokensAsync(string userId)
    {
        throw new NotImplementedException();
    }

    public virtual async Task<Result> RevokeTokenAsync(string token)
    {
        throw new NotImplementedException();
    }

    private SecurityTokenDescriptor GetAccessTokenDescriptor(IEnumerable<Claim> claims,
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresAt = null)
    {
        issuedAt ??= DateTimeOffset.UtcNow;

        var descriptor = new SecurityTokenDescriptor
        {
            Expires = (issuedAt.Value.AddMinutes(_jwtSettings.AccessToken.ExpiresInMinutes ?? 15)).UtcDateTime,
            NotBefore = notBefore.HasValue ? notBefore.Value.UtcDateTime : issuedAt.Value.UtcDateTime,
            IssuedAt = issuedAt.Value.UtcDateTime,
            Issuer = _jwtSettings.AccessToken.Issuers!.First(),
            Subject = new ClaimsIdentity(claims),

            // Source: https://stackoverflow.com/questions/71449622/add-multiple-audiences-in-token-descriptor
            Claims = new Dictionary<string, object>
            {
                { Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Aud, _jwtSettings.AccessToken.Audiences! },
            },
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.AccessToken.SecretKey ??
                throw new SecurityTokenInvalidSigningKeyException("Secret key is not found"))
            ), _jwtSettings.AccessToken.SigningAlgorithm)
        };
        return descriptor;
    }
}
