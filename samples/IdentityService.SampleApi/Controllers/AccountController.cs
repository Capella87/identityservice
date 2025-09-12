using IdentityService.Jwt;
using IdentityService.SampleApi.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using System.ComponentModel.DataAnnotations;

namespace IdentityService.SampleApi.Controllers;

[ApiController]
[Route("api/account/")]
public class AccountController : ControllerBase
{
    private readonly ILogger<AccountController> _logger;
    private readonly EmailAddressAttribute _emailAttr = new();
    private readonly ITokenService<IdentityUser<string>, string> _tokenService;
    private readonly AppDbContext _dbContext;
    private readonly SignInManager<IdentityUser<string>> _signInManager;

    public AccountController(AppDbContext dbContext,
        ILogger<AccountController> logger,
        ITokenService<IdentityUser<string>, string> tokenService,
        SignInManager<IdentityUser<string>> signInManager)
    {
        _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
    }

    [HttpPost("signup")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(IdentityResult), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public async virtual Task<IActionResult> SignUp([FromBody] SignUpRequestModel data, [FromServices] IServiceProvider sp)
    {
        var userManager = sp.GetRequiredService<UserManager<IdentityUser<string>>>();
        var userStore = sp.GetRequiredService<IUserStore<IdentityUser<string>>>();
        var emailStore = (IUserEmailStore<IdentityUser<string>>)userStore;
        var email = data.EmailAddress;

        if (string.IsNullOrEmpty(email) || !_emailAttr.IsValid(email))
        {
            var validationProblemDetails = CreateValidationProblemDetails(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(email)));
            return BadRequest(validationProblemDetails); // Explicitly return BadRequest with ValidationProblemDetails
        }

        var newUser = new IdentityUser();

        await userStore.SetUserNameAsync(newUser, data.Username, CancellationToken.None);
        await emailStore.SetEmailAsync(newUser, email, CancellationToken.None);
        var result = await userManager.CreateAsync(newUser, data.Password);

        if (!result.Succeeded)
        {
            var validationProblemDetails = CreateValidationProblemDetails(result);
            return BadRequest(validationProblemDetails); // Explicitly return BadRequest with ValidationProblemDetails
        }
        await userManager.AddToRoleAsync(newUser, "User");

        // TODO : Email confirmation logic can be added here. (Email is sent in prior.)

        return CreatedAtAction(nameof(SignUp), result);
    }

    // Login
    [HttpPost("login")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(JwtTokenResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> Login([FromBody] LoginRequestModel data)
    {
        if (HttpContext.User.Identity!.IsAuthenticated)
        {
            return Problem("You're already authenticated.", statusCode: StatusCodes.Status400BadRequest);
        }

        _signInManager.AuthenticationScheme = JwtBearerDefaults.AuthenticationScheme;

        // Convert Base64 password to plain password.

        var result = await _signInManager.PasswordSignInAsync(data.Username, data.Password, false, false);
        if (!result.Succeeded)
        {
            return Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
        }

        // All authentication and authorization works are done in SignInManager..., but we have to create a JWT token manually...
        // In the referred code, they returns TypedResults.Empty.
        return new EmptyResult();
    }

    // Logout
    [HttpPost("logout")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<IActionResult> Logout()
    {
        if (!HttpContext.User.Identity!.IsAuthenticated)
        {
            return Problem("You're not authenticated.", statusCode: StatusCodes.Status400BadRequest);
        }

        // Sign out the user
        _signInManager.AuthenticationScheme = JwtBearerDefaults.AuthenticationScheme;
        await _signInManager.SignOutAsync();

        if (HttpContext.Response.StatusCode == StatusCodes.Status500InternalServerError)
        {
            return Problem("An error occurred during logout.", statusCode: StatusCodes.Status500InternalServerError, title: "Sign-Out Failed");
        }
        else if (HttpContext.Response.StatusCode == StatusCodes.Status400BadRequest)
        {
            return Problem("Token is invalid or not provided.", statusCode: StatusCodes.Status400BadRequest, title: "Invalid request");
        }

        return Ok(new { Message = "Successfully logged out." });
    }

    [HttpPost("token/refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> RefreshAccessToken([FromBody] RefreshTokenRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            var problemDetails = new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Invalid Request",
                Detail = "Refresh token must be provided.",
                Instance = HttpContext.Request.Path
            };
            return BadRequest(problemDetails);
        }
        var tokenEntityResult = await _tokenService.GetTokenAsync(request.RefreshToken!);
        if (tokenEntityResult.IsFailed)
        {
            return Problem(tokenEntityResult.Errors.First().Message, statusCode: StatusCodes.Status400BadRequest, title: "Invalid refresh token");
        }

        // Check whether the time is not expired or not yet valid.
        var now = DateTimeOffset.UtcNow;
        if (now < tokenEntityResult.Value!.NotBefore || now > tokenEntityResult.Value.ExpiresAt)
        {
            return Problem("The refresh token is expired or not yet valid.", statusCode: StatusCodes.Status400BadRequest, title: "Invalid refresh token");
        }

        var tokenEntity = tokenEntityResult.Value as JwtRefreshTokenEntity<IdentityUser<string>, string>;
        var claims = await _signInManager.CreateUserPrincipalAsync(tokenEntity!.User!);

        var result = await _tokenService.RefreshTokenAsync(request.RefreshToken!, claims);
        if (result.IsFailed)
        {
            return Problem(result.Errors.First().Message, statusCode: StatusCodes.Status400BadRequest, title: "Failed to refresh the access token");
        }

        return Ok(result.Value);
    }


    private static ValidationProblemDetails CreateValidationProblemDetails(IdentityResult result)
    {
        var errorDict = new Dictionary<string, string[]>(1);

        foreach (var error in result.Errors)
        {
            string[] newStatements;

            if (errorDict.TryGetValue(error.Code, out var descs))
            {
                newStatements = new string[descs.Length + 1];
                Array.Copy(descs, newStatements, descs.Length);
                newStatements[descs.Length] = error.Description;
            }
            else
            {
                newStatements = [error.Description];
            }

            errorDict[error.Code] = newStatements;
        }

        return new ValidationProblemDetails(errorDict);
    }
}
