using FluentResults;
using IdentityService.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityService.Data;

/// <summary>
/// A repository for managing JWT tokens using Entity Framework Core and database providers.
/// </summary>
/// <typeparam name="TUser"></typeparam>
/// <typeparam name="UserKey"></typeparam>
public class JwtTokenRepository<TUser, UserKey> : ITokenRepository
    where TUser : IdentityUser<UserKey>
    where UserKey : IEquatable<UserKey>
{
    private readonly DbContext _dbContext;

    public JwtTokenRepository(DbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<Result> DeleteTokenAsync(IToken token)
    {
        _dbContext.Set<JwtRefreshTokenEntity<TUser, UserKey>>().Remove((token as JwtRefreshTokenEntity<TUser, UserKey>)!);
        await _dbContext.SaveChangesAsync();

        return Result.Ok();
    }

    public async Task<Result<IToken?>> GetTokenAsync(string token)
    {
        var result = await _dbContext.Set<JwtRefreshTokenEntity<TUser, UserKey>>()
            .Include(e => e.User)
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Token == token);

        return result ?? (Result<IToken?>)Result.Fail("Token not found");
    }

    public Task<Result<IEnumerable<IToken>?>> GetTokensByUserIdAsync(string userId)
    {
        // Find all tokens;
        throw new NotImplementedException();
    }

    public async  Task<Result<T?>> GetUserByIdAsync<T>(string userId) where T : class
    {
        var result = await _dbContext.Set<T>().FindAsync(userId);

        return result ?? (Result<T?>)Result.Fail("User not found");
    }

    public async Task<Result> RevokeAllTokensByUserIdAsync(string userId)
    {
        var results = await _dbContext.Set<JwtRefreshTokenEntity<TUser, UserKey>>()
            .Where(t => t.UserId!.ToString() == userId)
            .ToListAsync();
        if (results.Count == 0)
        {
            return Result.Ok();
        }

        _dbContext.Set<JwtRefreshTokenEntity<TUser, UserKey>>().RemoveRange(results);
        await _dbContext.SaveChangesAsync();

        return Result.Ok();
    }

    public Task<Result> RevokeTokenAsync(IToken token)
    {
        var entity = token as JwtRefreshTokenEntity<TUser, UserKey>;
        _dbContext.Set<JwtRefreshTokenEntity<TUser, UserKey>>().Remove(entity!);

        return _dbContext.SaveChangesAsync().ContinueWith(t =>
        {
            if (t.IsFaulted)
            {
                return Result.Fail(t.Exception?.Message ?? "Failed to revoke token");
            }
            return Result.Ok();
        });
    }

    public Task<Result> SaveTokenAsync(IToken token)
    {
        var entity = token as JwtRefreshTokenEntity<TUser, UserKey>;
        _dbContext.Set<JwtRefreshTokenEntity<TUser, UserKey>>().Add(entity!);
        return _dbContext.SaveChangesAsync().ContinueWith(t =>
        {
            if (t.IsFaulted)
            {
                return Result.Fail(t.Exception?.Message ?? "Failed to save token");
            }
            return Result.Ok();
        });
    }
}
