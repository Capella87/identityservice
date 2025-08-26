using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityService.Jwt;

public class JwtRefreshTokenEntity<TUser, UserKey> : JwtRefreshToken
    where TUser : IdentityUser<UserKey>
    where UserKey : IEquatable<UserKey>
{
    [ForeignKey(nameof(User))]
    public UserKey? UserId { get; set; }

    public TUser? User { get; set; }
}
