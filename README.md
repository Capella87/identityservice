# IdentityService
An Token Based Authentication Library integrated into ASP.NET Core Identity. Currently supports JWT with `IdentityService.Jwt`.

> [!CAUTION]
> This project is still under development and breaking changes occur frequently. It may be not working well that certain features or APIs on future releases.

## Disclaimer
This software is distributed on as an open source software under the MIT License.
See the LICENSE file for details.

You can use this software for free, but please be aware that it comes with no warranty or support.

## Features

* **ASP.NET Core Identity Integration**: You can use Identity's built-in user management systems with JWT authentication!
* JWT Token Creation (With various algorithms)
* Refresh Token with rotation
* Token Revocation

## Getting Started

IdentityService supports .NET 8.0 and 9.0 as of September 2025. Please follow the steps below to configure the library.

### Requirements

* .NET 8.0 or 9.0 SDK
* EF Core
* Database supported by EF Core. (It is recommended to use PostgreSQL)
* `Microsoft.IdentityModel.Tokens`
* `Microsoft.Extensions.Identity.Core`
* `Microsoft.AspNetCore.Identity.EntityFrameworkCore`

### Installation
You can install IdentityService from NuGet Gallery by nuget CLI or dotnet CLI.

Remember that you need to install Jwt package to make use of JWT authentication.

```powershell
dotnet add package Capelladev.IdentityService --version 0.1.0
dotnet add package Capelladev.IdentityService.Jwt --version 0.1.0
```

### `appsettings.json` Configuration

Add a configuration section for JWT settings in your project's `appsettings.json` file:
```json
{
  "JwtSettings": {
    "AccessToken": {
      "ValidateIssuer": true,
      "ValidateIssuerSigningKey": true,
      "Issuers": [
        "https://localhost:22000"
      ],
      "ValidateAudience": true,
      "Audiences": [
        "https://localhost:22000",
        "http://localhost:10586"
      ],
      "SecretKey": "your-secret-key",
      "SigningAlgorithm": "HS256",
      "ExpiresInMinutes": 20
    },
    "RefreshToken": {
      "EnableRefreshToken": true,
      "ExpiresInMinutes": 10080
    }
  }
}
```

### `DbContext` and Repository Setup
This library is integrated to ASP.NET Core Identity, So it is strongly recommended to use `IdentityDbContext`.

You need to add `DbSet` for the refresh token entity to your `DbContext` class. Remember that please specify the user and key type.
For example:
```csharp
public DbSet<JwtRefreshTokenEntity<IdentityUser<string>, string>> RefreshTokens { get; set; }
```
You can use your custom user class based on `IdentityUser` as well.

### Identity Setup
Only **3** methods are required to set up JWT authentication.

1. Register `JwtSettings` configuration to the DI container.
```csharp
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
```

2. Add `ITokenRepository` implementation to the DI container.
For instance, If you want to register JWT token, Register `JwtTokenRepository` with your user class and DbContext as a scoped service
```csharp
builder.Services.AddScoped<ITokenRepository, JwtTokenRepository<IdentityUser<string>, string>>(sp =>
    new JwtTokenRepository<IdentityUser<string>, string>(sp.GetRequiredService<AppDbContext>()));
```

3. Add an extension method for each token systems. For JWT, call `AddJwtTokenIdentity`.
```csharp
builder.Services.AddJwtTokenIdentity<IdentityUser<string>, string>(builder.Configuration);
```

As of v0.1.0, IdentityService has extension methods including not only JWT configuration but also default configurations for ASP.NET Core Identity.
Instead of `AddIdentity` or `AddDefaultIdentity`, **Just invoke `AddJwtTokenIdentity`**. Even `setupActions` parameter works!

For JWT:
```csharp
builder.Services.AddJwtTokenIdentity<IdentityUser<string>, IdentityRole, string>(options =>
{
    options.User.RequireUniqueEmail = true;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 15;
    options.Password.RequireNonAlphanumeric = false;
})
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();
```

For the customized ASP.NET Core Identity configuration, you can utilize `Add[TokenSystem]Token` method along with customized code.
For JWT, Add `AddJwtToken`.

4. Done. Don't forget to inject token service you want to use! There's a sample project with the configuration in samples directory.

## Feedback

Feel free to open issues or submit pull requests on GitHub. I welcome any issues or contributions for the better software.

---

Copyright © 2025 Capella87. Distributed under the MIT License.
