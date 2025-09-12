using IdentityService.Jwt.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityService.Jwt.Extensions;

public static class JwtTokenExtensions
{
    public static AuthenticationBuilder AddJwtToken<TUser, UserKey>(this AuthenticationBuilder builder)
        where TUser : IdentityUser<UserKey>
        where UserKey : IEquatable<UserKey>
        => builder.AddJwtToken<TUser, UserKey>(JwtBearerDefaults.AuthenticationScheme, options => { });

    public static AuthenticationBuilder AddJwtToken<TUser, UserKey>(this AuthenticationBuilder builder, string authenticationScheme)
        where TUser : IdentityUser<UserKey>
        where UserKey : IEquatable<UserKey>
        => builder.AddJwtToken<TUser, UserKey>(authenticationScheme, _ => { });

    public static AuthenticationBuilder AddJwtToken<TUser, UserKey>(this AuthenticationBuilder builder, Action<JwtBearerOptions> configureOptions)
        where TUser : IdentityUser<UserKey>
        where UserKey : IEquatable<UserKey>
        => builder.AddJwtToken<TUser, UserKey>(JwtBearerDefaults.AuthenticationScheme, configureOptions);

    public static AuthenticationBuilder AddJwtToken<TUser, UserKey>(this AuthenticationBuilder builder, string authenticationScheme,
        Action<JwtBearerOptions> configureOptions)
        where TUser : IdentityUser<UserKey>
        where UserKey : IEquatable<UserKey>
        => builder.AddJwtToken<TUser, UserKey>(authenticationScheme, null, configureOptions);

    public static AuthenticationBuilder AddJwtToken<TUser, UserKey>(this AuthenticationBuilder builder,
        string authenticationScheme,
        string? displayName,
        Action<JwtBearerOptions> configureOptions)
        where TUser : IdentityUser<UserKey>
        where UserKey : IEquatable<UserKey>
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(authenticationScheme);
        ArgumentNullException.ThrowIfNull(configureOptions);

        builder.Services.TryAddScoped<ITokenService<TUser, UserKey>, JwtTokenService<TUser, UserKey>>();

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<JwtBearerOptions>, JwtTokenConfigureOptions>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerPostConfigureOptions>());
        return builder.AddScheme<JwtBearerOptions, JwtTokenHandler<TUser, UserKey>>(authenticationScheme, displayName, configureOptions);
    }
}
