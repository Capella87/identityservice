using IdentityService;
using IdentityService.Data;
using IdentityService.Jwt;
using IdentityService.Jwt.Extensions;
using IdentityService.SampleApi.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi;
using Serilog;
using Serilog.Events;
using System;
using System.Text.Json;

var configuration = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddEnvironmentVariables()
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true, reloadOnChange: true)
    .Build();

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(configuration)
    .CreateLogger();

try
{
    Log.Information("Starting the host...");
    var builder = WebApplication.CreateBuilder(args);
    builder.Configuration.AddConfiguration(configuration);
    builder.Services.AddSerilog();

    builder.Services.Configure<RouteOptions>(o =>
    {
        o.LowercaseUrls = true;
        o.AppendTrailingSlash = true;
        o.LowercaseQueryStrings = true;
    });

    builder.Services.AddProblemDetails();
    builder.Services.AddAntiforgery();
    builder.Services.AddCors();

    if (builder.Environment.IsDevelopment())
    {
        builder.Services.AddHealthChecks();
    }

    // Add services to the container.

    // Configure DbContext with PostgreSQL
    builder.Services.AddDbContext<AppDbContext>(options =>
    {
        options.UseNpgsql(builder.Configuration.GetConnectionString(builder.Configuration["ConnectionStringProfile"] ?? "DefaultConnection"),
            npgsqlOptions =>
            {
                npgsqlOptions.EnableRetryOnFailure();
            });
    });
    builder.Services.AddJwtTokenIdentity<IdentityUser, IdentityRole<string>>(options =>
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

    // Note: This is Controller-based MVC Web API.
    // For Minimal APIs, you should set JSON options with `builder.Services.ConfigureHttpJsonOptions`
    builder.Services.AddControllers()
        .AddJsonOptions(options =>
        {
            options.JsonSerializerOptions.AllowTrailingCommas = false;
            options.AllowInputFormatterExceptionMessages = true;
            options.JsonSerializerOptions.AllowOutOfOrderMetadataProperties = false;
            options.JsonSerializerOptions.ReadCommentHandling = JsonCommentHandling.Skip;
            options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
        });
    // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddOpenApi(options =>
    {
        options.OpenApiVersion = OpenApiSpecVersion.OpenApi3_0;
    });

    var app = builder.Build();
    app.UseRouting();
    app.UseSerilogRequestLogging((opts) =>
    {
        opts.MessageTemplate = "{Protocol} {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";
        opts.GetMessageTemplateProperties = (HttpContext httpContext, string requestPath, double elapsedMs, int statusCode) =>
        [
            new LogEventProperty("Protocol", new ScalarValue(httpContext.Request.Protocol)),
            new LogEventProperty("RequestMethod", new ScalarValue(httpContext.Request.Method)),
            new LogEventProperty("RequestPath", new ScalarValue(requestPath)),
            new LogEventProperty("StatusCode", new ScalarValue(statusCode)),
            new LogEventProperty("Elapsed", new ScalarValue(elapsedMs)),
            new LogEventProperty("UserAgent", new ScalarValue(httpContext.Request.Headers[HeaderNames.UserAgent].ToString())),
            new LogEventProperty("ContentType", new ScalarValue(httpContext.Request.ContentType)),
        ];
    });

    // Use redirection to non-www URLs with 301 Moved Permanently status code.
    app.UseRewriter(new RewriteOptions()
        .AddRedirectToNonWwwPermanent());

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.MapOpenApi();
        //app.MapScalarApiReference("openapi/scalar", config =>
        //{
        //    config.Theme = ScalarTheme.BluePlanet;
        //    config.HideModels = true;
        //    config.HideDarkModeToggle = false;
        //});
        app.UseDeveloperExceptionPage();
        app.MapHealthChecks("/healthchecks");
    }
    else
    {
        app.UseExceptionHandler("/error");
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseCors();
    app.UseAntiforgery();
    app.UseStatusCodePages();
    app.UseStaticFiles();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();
    app.Run();
}
catch (Exception ex) when (ex is not HostAbortedException && ex.Source != "Microsoft.EntityFrameworkCore.Design")
{
    Log.Fatal(ex, "The WebApplication host terminated unexpectedly...");
}
catch (HostAbortedException ex) when (ex.Source != "Microsoft.EntityFrameworkCore.Design")
{
    Log.Fatal(ex, "The WebApplication host is aborted...");
}
finally
{
    Log.Information("Closing the logger...");
    Log.CloseAndFlush();
}
