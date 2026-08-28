using Microsoft.AspNetCore.Mvc;
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
    private const long UploadLimitBytes = 12L * 1024 * 1024;

    private readonly PdfSecurity _pdfSecurity;
    private readonly ILogger<PdfController> _logger;

    public PdfController(PdfSecurity pdfSecurity, ILogger<PdfController> logger)
    {
        _pdfSecurity = pdfSecurity;
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
    [RequestSizeLimit(UploadLimitBytes)]
    [Produces("application/json")]
    public async Task<ActionResult<PdfScanResponse>> Validate([FromForm] IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest(new PdfScanResponse(false, false, null, 0, "No file was uploaded.", ["No file (or an empty file) was uploaded in the 'file' form field."], []));
        }

        // Fast, cheap pre-checks: extension + content type before reading the whole payload.
        var ext = Path.GetExtension(file.FileName);
        if (!string.Equals(ext, ".pdf", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new PdfScanResponse(false, false, file.FileName, file.Length,
                "Only PDF files are accepted.",
                [$"Unsupported file extension '{ext}'. Please upload a .pdf file."], []));
        }

        if (!string.IsNullOrEmpty(file.ContentType) &&
            !file.ContentType.Equals("application/pdf", StringComparison.OrdinalIgnoreCase) &&
            !file.ContentType.Equals("application/x-pdf", StringComparison.OrdinalIgnoreCase) &&
            !file.ContentType.Equals("text/pdf", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new PdfScanResponse(false, false, file.FileName, file.Length,
                "Only PDF files are accepted.",
                [$"Unsupported content type '{file.ContentType}'. Expected application/pdf."], []));
        }

        byte[] bytes;
        await using (var ms = new MemoryStream())
        {
            await file.CopyToAsync(ms);
            bytes = ms.ToArray();
        }

        var result = _pdfSecurity.Validate(bytes, file.FileName);

        if (!result.IsAllowed)
        {
            _logger.LogWarning("PDF rejected '{File}' ({Size} bytes): {Summary}",
                file.FileName, result.SizeBytes, result.Summary);
            return Ok(PdfScanResponse.From(result));
        }

        _logger.LogInformation("PDF accepted '{File}' ({Size} bytes).", file.FileName, result.SizeBytes);
        return Ok(PdfScanResponse.From(result));
    }
}
