using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace IdentityService.SampleApi;

public class SignUpRequestModel
{
    [Required(ErrorMessage = "Username is required.")]
    [JsonPropertyName("username")]
    public required string Username { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    [JsonPropertyName("password")]
    public required string Password { get; set; }

    [Required(ErrorMessage = "EmailAddress is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    [JsonPropertyName("email")]
    public required string EmailAddress { get; set; }
}
