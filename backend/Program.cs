using Microsoft.AspNetCore.Http.Features;
using PdfSecurityApi.Security;

var builder = WebApplication.CreateBuilder(args);

// Bind the "PdfSecurity" configuration section and register the scanner as a singleton.
builder.Services.Configure<PdfSecurityOptions>(builder.Configuration.GetSection("PdfSecurity"));
builder.Services.AddSingleton<PdfSecurity>();

builder.Services.AddControllers();

// Avoid the default Windows EventLog provider: it cannot write the Windows Event Log here
// ("Access is denied"), and that failure was aborting requests that logged a rejection.
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Allow the React/TS dev server (and any origin in demos) to call the API.
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader());
});

// Keep the multipart body limit in sync with the scanner's max file size.
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 12L * 1024 * 1024;
    options.ValueLengthLimit = int.MaxValue;
});

var app = builder.Build();

app.UseCors("AllowFrontend");
app.MapControllers();

app.Run();

// Exposed so integration tests can spin the same host up.
public partial class Program { }
