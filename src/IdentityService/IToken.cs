using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityService;
public interface IToken
{
    public string Id { get; set; }

    public string Token { get; set; }

    public DateTimeOffset? ExpiredAt { get; set; }

    public DateTimeOffset? IssuedAt { get; set; }

    public DateTimeOffset? NotBefore { get; set; }
}

public interface IToken<TSecurityToken> : IToken where TSecurityToken : SecurityToken
{
    public TSecurityToken SecurityToken { get; set; }
}
