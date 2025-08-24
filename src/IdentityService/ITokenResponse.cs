using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityService;

public interface ITokenResponse
{
    public string AccessToken { get; set; }

    public DateTimeOffset AccessTokenExpiresAt { get; set; }

    public string? RefreshToken { get; set; }

    public DateTimeOffset? RefreshTokenExpiresAt { get; set; }
}
