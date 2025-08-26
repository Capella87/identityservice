using System.ComponentModel.DataAnnotations;

namespace IdentityService.Jwt;

public class JwtRefreshToken : IToken
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public required string Token { get; set; }

    public DateTimeOffset? ExpiresAt { get; set; }

    public DateTimeOffset? IssuedAt { get; set; }

    public DateTimeOffset? NotBefore { get; set; }
}
