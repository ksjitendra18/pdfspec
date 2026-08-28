using PdfSecurityApi.Security;

namespace PdfSecurityApi.Models;

/// <summary>API response returned by the PDF upload / validate endpoint.</summary>
public sealed record PdfScanResponse(
    bool Allowed,
    bool IsValidPdf,
    string? FileName,
    long SizeBytes,
    string Summary,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<PdfFinding> Findings)
{
    public static PdfScanResponse From(PdfValidationResult result) => new(
        result.IsAllowed,
        result.IsValidPdf,
        result.FileName,
        result.SizeBytes,
        result.Summary,
        result.Reasons,
        result.Findings);
}
