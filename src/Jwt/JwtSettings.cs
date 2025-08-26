using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace IdentityService.Jwt;

public class JwtSettings
{
    [JsonPropertyName("AccessToken")]
    public AccessTokenSettings AccessToken { get; set; } = default!;

    [JsonPropertyName("RefreshToken")]
    public RefreshTokenSettings RefreshToken { get; set; } = default!;
}

public class AccessTokenSettings
{
    public bool? ValidateIssuers { get; set; } = true;

    public bool? ValidateIssuerSigningKey { get; set; } = true;

    public bool? ValidateAudiences { get; set; } = true;

    public IEnumerable<string>? Issuers { get; set; }

    public IEnumerable<string>? Audiences { get; set; }

    public required string SecretKey { get; set; }

    public long? ExpiresInMinutes { get; set; } = 15;

    public string? SigningAlgorithm { get; set; }
}

public class RefreshTokenSettings
{
    public bool? EnableRefreshToken { get; set; } = false;

    public long? ExpiresInMinutes { get; set; } = 10_080;

    public string? ConnectionProfile { get; set; } = "DefaultConnection";
}
