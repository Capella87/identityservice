using FluentResults;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityService.Data;

/// <summary>
/// An interface for a token repository to manage tokens.
/// </summary>
public interface ITokenRepository
{
    public Task<Result<IToken?>> GetTokenAsync(string token);

    public Task<Result<IEnumerable<IToken>?>> GetTokensByUserIdAsync(string userId);

    public Task<Result> RevokeTokenAsync(IToken token);

    public Task<Result> RevokeAllTokensByUserIdAsync(string userId);

    public Task<Result> SaveTokenAsync(IToken token);

    public Task<Result> DeleteTokenAsync(IToken token);

    public Task<Result<T?>> GetUserByIdAsync<T>(string userId) where T : class;
}
