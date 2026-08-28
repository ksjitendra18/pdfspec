using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using PdfSecurityApi.Models;
using PdfSecurityApi.Security;

namespace PdfSecurityApi.Controllers;

/// <summary>
/// Endpoint that accepts a PDF upload, runs every file through <see cref="PdfSecurity"/>,
/// and returns a verdict. Dangerous documents are rejected and never stored.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class PdfController : ControllerBase
{
    private readonly PdfSecurity _pdfSecurity;
    private readonly PdfSecurityOptions _options;
    private readonly ILogger<PdfController> _logger;

    public PdfController(PdfSecurity pdfSecurity, IOptions<PdfSecurityOptions> options, ILogger<PdfController> logger)
    {
        _pdfSecurity = pdfSecurity;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>Simple health probe so the front end can confirm the API is reachable.</summary>
    [HttpGet("health")]
    [Produces("application/json")]
    public IActionResult Health() => Ok(new { status = "ok", service = "PdfSecurityApi" });

    /// <summary>
    /// Validate (and, when safe, accept) an uploaded PDF.
    /// The file must be multipart/form-data with a field named <c>file</c>.
    /// </summary>
    /// <response code="200">Validation finished. <c>allowed</c> indicates whether the PDF may be accepted.</response>
    /// <response code="400">The request is missing the file or the file is not a PDF.</response>
    [HttpPost("validate")]
    [Consumes("multipart/form-data")]
    [EnableRateLimiting("pdf-scan")]
    [RequestTimeout("pdf-scan")]
    [Produces("application/json")]
    public async Task<ActionResult<PdfScanResponse>> Validate([FromForm] IFormFile? file, CancellationToken cancellationToken)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest(new PdfScanResponse(false, false, null, 0, "No file was uploaded.", ["No file (or an empty file) was uploaded in the 'file' form field."], []));
        }

        // Fast, cheap pre-checks: extension + content type before reading the whole payload.
        var displayName = SanitizeFileName(file.FileName);
        var ext = Path.GetExtension(displayName);
        if (!string.Equals(ext, ".pdf", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new PdfScanResponse(false, false, displayName, file.Length,
                "Only PDF files are accepted.",
                [$"Unsupported file extension '{ext}'. Please upload a .pdf file."], []));
        }

        if (!string.IsNullOrEmpty(file.ContentType) &&
            !file.ContentType.Equals("application/pdf", StringComparison.OrdinalIgnoreCase) &&
            !file.ContentType.Equals("application/x-pdf", StringComparison.OrdinalIgnoreCase) &&
            !file.ContentType.Equals("text/pdf", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new PdfScanResponse(false, false, displayName, file.Length,
                "Only PDF files are accepted.",
                [$"Unsupported content type '{file.ContentType}'. Expected application/pdf."], []));
        }

        if (file.Length > _options.MaxFileSizeBytes)
        {
            return StatusCode(StatusCodes.Status413PayloadTooLarge,
                new PdfScanResponse(false, false, displayName, file.Length, "File too large.",
                    [$"The maximum allowed file size is {_options.MaxFileSizeBytes:N0} bytes."], []));
        }

        await using var ms = new MemoryStream(checked((int)file.Length));
        await file.CopyToAsync(ms, cancellationToken);
        var bytes = ms.GetBuffer();
        var result = _pdfSecurity.Validate(bytes, checked((int)ms.Length), displayName, cancellationToken);

        if (!result.IsAllowed)
        {
            _logger.LogWarning("PDF rejected '{File}' ({Size} bytes): {Summary}",
                displayName, result.SizeBytes, result.Summary);
            return Ok(PdfScanResponse.From(result));
        }

        _logger.LogInformation("PDF accepted '{File}' ({Size} bytes).", displayName, result.SizeBytes);
        return Ok(PdfScanResponse.From(result));
    }

    private static string SanitizeFileName(string fileName)
    {
        var name = Path.GetFileName(fileName);
        name = new string(name.Where(character => !char.IsControl(character)).ToArray());
        return name.Length <= 255 ? name : name[..255];
    }
}
