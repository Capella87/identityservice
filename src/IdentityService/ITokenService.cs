using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using FluentResults;
using Microsoft.IdentityModel.Tokens;

namespace IdentityService;

public interface ITokenService
{
    public Task<Result<ITokenResponse?>> CreateTokenAsync(string userId, ClaimsPrincipal user);
    
    public Task<Result<ITokenResponse?>> RefreshTokenAsync(string refreshToken);

    public Task<Result<IToken?>> GetTokenAsync(string token);

    public Task<Result> RevokeTokenAsync(string token);

    public Task<Result> RevokeAllUserTokensAsync(string userId);

    public Task<Result<SecurityToken>> GenerateAccessTokenAsync(IEnumerable<Claim> claims,
        DateTimeOffset? issuedAt,
        DateTimeOffset? expiredAt,
        DateTimeOffset? notBefore);

    public Task<Result<IToken?>> GenerateRefreshTokenAsync(DateTimeOffset? issuedAt,
        DateTimeOffset? expiredAt,
        DateTimeOffset? notBefore);
}
