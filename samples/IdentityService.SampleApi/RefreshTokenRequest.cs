using System.Text.Json.Serialization;

namespace IdentityService.SampleApi;

public class RefreshTokenRequest
{
    [JsonPropertyName("RefreshToken")]
    public string? RefreshToken { get; set; }
}
