using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityService.Jwt;

/// <summary>
/// Represents a JWT refresh token entity that is associated with a user for database providers.
/// </summary>
/// <typeparam name="TUser"></typeparam>
/// <typeparam name="UserKey"></typeparam>
public class JwtRefreshTokenEntity<TUser, UserKey> : JwtRefreshToken
    where TUser : IdentityUser<UserKey>
    where UserKey : IEquatable<UserKey>
{
    [ForeignKey(nameof(User))]
    public UserKey? UserId { get; set; }

    public TUser? User { get; set; }

    public DateTimeOffset? RevokedAt { get; set; } = null;
}

public class JwtRefreshTokenEntity<TUser> : JwtRefreshTokenEntity<TUser, string>
    where TUser : IdentityUser<string>
{
}

public class JwtRefreshTokenEntity : JwtRefreshTokenEntity<IdentityUser<string>>
{
}
