using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using FluentResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace IdentityService;

/// <summary>
/// A token service interface for creating, refreshing, retrieving, and revoking tokens.
/// </summary>
public interface ITokenService
{
    public Task<Result<ITokenResponse?>> CreateTokenAsync(string userId, ClaimsPrincipal user);

    public Task<Result<ITokenResponse?>> RefreshTokenAsync(IToken refreshToken, ClaimsPrincipal user);

    public Task<Result<IToken?>> GetTokenAsync(string token);

    public Task<Result> RevokeTokenAsync(string token);

    public Task<Result> RevokeAllUserTokensAsync(string userId);

    public Task<Result<SecurityToken>> GenerateAccessTokenAsync(IEnumerable<Claim> claims,
        DateTimeOffset? issuedAt,
        DateTimeOffset? expiresAt,
        DateTimeOffset? notBefore);

    public Task<Result<IToken?>> GenerateRefreshTokenAsync(DateTimeOffset? issuedAt,
        DateTimeOffset? expiresAt,
        DateTimeOffset? notBefore);
}

public interface ITokenService<TUser, TKey> : ITokenService
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
{

}
