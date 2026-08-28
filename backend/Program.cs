using Microsoft.AspNetCore.Http.Features;
using System.Threading.RateLimiting;
using PdfSecurityApi.Security;

var builder = WebApplication.CreateBuilder(args);

// Bind the "PdfSecurity" configuration section and register the scanner as a singleton.
builder.Services.AddOptions<PdfSecurityOptions>()
    .Bind(builder.Configuration.GetSection("PdfSecurity"))
    .Validate(options => options.MaxFileSizeBytes is > 0 and <= int.MaxValue,
        "MaxFileSizeBytes must be between 1 and Int32.MaxValue.")
    .Validate(options => options.MaxInflateBytes > 0 &&
                         options.MaxTotalInflateBytes >= options.MaxInflateBytes,
        "Decoded stream limits are invalid.")
    .Validate(options => options.MaxStreamCount > 0 && options.MaxCompressionRatio > 0 && options.MaxFindings > 0,
        "Scanner count limits must be positive.")
    .ValidateOnStart();
builder.Services.AddSingleton<PdfSecurity>();

builder.Services.AddControllers();

// Avoid the default Windows EventLog provider: it cannot write the Windows Event Log here
// ("Access is denied"), and that failure was aborting requests that logged a rejection.
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

var frontendOrigins = builder.Configuration.GetSection("FrontendOrigins").Get<string[]>()
    ?? ["http://localhost:5173"];

// Only explicitly configured frontends may read API responses cross-origin.
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
        policy.WithOrigins(frontendOrigins)
              .WithMethods("GET", "POST")
              .AllowAnyHeader());
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetConcurrencyLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new ConcurrencyLimiterOptions
            {
                PermitLimit = 8,
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    options.AddPolicy("pdf-scan", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});

builder.Services.AddRequestTimeouts(options =>
    options.AddPolicy("pdf-scan", TimeSpan.FromSeconds(15)));

// Keep the multipart body limit in sync with the scanner's max file size.
var configuredUploadLimit = builder.Configuration.GetValue<long?>("PdfSecurity:MaxFileSizeBytes")
    ?? 10L * 1024 * 1024;
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = configuredUploadLimit + 1024 * 1024;
});

var app = builder.Build();

app.UseCors("AllowFrontend");
app.UseRateLimiter();
app.UseRequestTimeouts();
app.MapControllers();

app.Run();

// Exposed so integration tests can spin the same host up.
public partial class Program { }
