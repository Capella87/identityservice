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
using Microsoft.AspNetCore.Identity;

using IdentityService.Data;
using Microsoft.AspNetCore.Http.HttpResults;

namespace IdentityService.Jwt;

/// <summary>
/// A service for creating and managing JWT token and refresh tokens.
/// </summary>
/// <typeparam name="TUser"></typeparam>
/// <typeparam name="TKey"></typeparam>
public class JwtTokenService<TUser, TKey> : ITokenService<TUser, TKey>
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
{
    private readonly IConfiguration _config;
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<JwtTokenService<TUser, TKey>> _logger;
    private readonly JsonWebTokenHandler _jwtHandler;
    private readonly ITokenRepository _tokenRepository;

    public JwtTokenService(IConfiguration config, ILogger<JwtTokenService<TUser, TKey>> logger,
        IOptions<JwtSettings> jwtSettings,
        ITokenRepository tokenRepository)
    {
        _config = config;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
        _tokenRepository = tokenRepository;
        _jwtHandler = new JsonWebTokenHandler()
        {
            MapInboundClaims = JwtSecurityTokenHandler.DefaultMapInboundClaims,
        };
    }

    /// <summary>
    /// Creates a new JWT token and a refresh token if enabled.
    /// </summary>
    /// <param name="userId"></param>
    /// <param name="user"></param>
    /// <returns></returns>
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

            var refreshTokenEntity = new JwtRefreshTokenEntity<TUser, TKey>
            {
                Id = refreshToken!.Id,
                Token = refreshToken.Token,
                IssuedAt = refreshToken.IssuedAt,
                NotBefore = refreshToken.NotBefore,
                ExpiresAt = refreshToken.ExpiresAt,
                UserId = (TKey)Convert.ChangeType(userId, typeof(TKey))
            };
            var lookupResult = await LookupUserByUserIdAsync(userId);

            if (lookupResult.IsFailed)
            {
                return Result.Fail(lookupResult.Errors);
            }
            refreshTokenEntity!.User = lookupResult.Value;

            // Connect to the database and save the token.
            var saveResult = await _tokenRepository.SaveTokenAsync(refreshTokenEntity);
            if (saveResult.IsFailed)
            {
                return Result.Fail(saveResult.Errors);
            }
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
    /// Generates a new refresh token. Remember that you must set time to issue.
    /// </summary>
    /// <param name="issuedAt"></param>
    /// <param name="expiresAt"></param>
    /// <param name="notBefore"></param>
    /// <returns>The successfully created IToken. If it is failed to create a refresh token, returns null.</returns>
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
        var result = await _tokenRepository.GetTokenAsync(token);
        if (result.IsFailed)
        {
            return Result.Fail("Token not found.");
        }
        return Result.Ok(result.Value);
    }

    public async Task<Result<ITokenResponse?>> RefreshTokenAsync(IToken refreshToken, ClaimsPrincipal user)
    {
        var token = refreshToken as JwtRefreshTokenEntity<TUser, TKey>;

        if (token == null)
        {
            return Result.Fail("Invalid token type.");
        }

        // Revoke the refresh token
        var revokeResult = await RevokeTokenAsync(token.Token);

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

        var tokenEntity = new JwtRefreshTokenEntity<TUser, TKey>
        {
            Token = rTokenResult.Value!.Token,
            IssuedAt = rTokenResult.Value!.IssuedAt,
            NotBefore = rTokenResult.Value!.NotBefore,
            ExpiresAt = rTokenResult.Value!.ExpiresAt,
            UserId = token.UserId,
            Id = rTokenResult.Value!.Id
        };

        // Save the refresh token to the database
        var result = await _tokenRepository.SaveTokenAsync(tokenEntity);

        if (result.IsFailed)
        {
            return Result.Fail(result.Errors);
        }

        var issuedAt = DateTimeOffset.UtcNow;
        var accessTokenResult = await GenerateAccessTokenAsync(user.Claims,
            issuedAt,
            issuedAt.AddMinutes(
                _jwtSettings.AccessToken.ExpiresInMinutes ?? 15),
            issuedAt);

        if (accessTokenResult.IsFailed)
        {
            return Result.Fail(accessTokenResult.Errors);
        }

        return Result.Ok<ITokenResponse?>(new JwtTokenResponse
        {
            AccessToken = (accessTokenResult.Value as JsonWebToken)!.EncodedToken,
            AccessTokenExpiresAt = accessTokenResult.Value.ValidTo,
            RefreshToken = tokenEntity.Token,
            RefreshTokenExpiresAt = tokenEntity.ExpiresAt,
        });
    }

    public virtual async Task<Result> RevokeAllUserTokensAsync(string userId)
    {
        var tokenLookupResult = await _tokenRepository.GetTokensByUserIdAsync(userId);
        if (tokenLookupResult.IsFailed)
        {
            return Result.Fail(tokenLookupResult.Errors);
        }

        var revokeResult = await _tokenRepository.RevokeAllTokensByUserIdAsync(userId);
        if (revokeResult.IsFailed)
        {
            return Result.Fail(revokeResult.Errors);
        }
        return Result.Ok();
    }

    public virtual async Task<Result> RevokeTokenAsync(string token)
    {
        var result = await _tokenRepository.GetTokenAsync(token);
        if (result.IsFailed)
        {
            return Result.Fail("Token not found.");
        }

        var revokeResult = await _tokenRepository.RevokeTokenAsync(result.Value!);
        if (revokeResult.IsFailed)
        {
            return Result.Fail(revokeResult.Errors);
        }

        return Result.Ok();
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

    private async Task<Result<TUser?>> LookupUserByUserIdAsync(string userId)
    {
        var result = await _tokenRepository.GetUserByIdAsync<TUser>(userId);

        if (result.IsFailed)
        {
            return Result.Fail(result.Errors);
        }

        return result.Value;
    }
}
