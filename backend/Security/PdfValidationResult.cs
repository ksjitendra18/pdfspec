namespace PdfSecurityApi.Security;

/// <summary>Value object describing a single dangerous construct found in a PDF.</summary>
public sealed record PdfFinding(string Rule, string Severity, string Detail);

/// <summary>
/// The verdict produced by <see cref="PdfSecurity.Validate(byte[], string?)"/>.
/// </summary>
public sealed class PdfValidationResult
{
    /// <summary>true when the bytes look like a real PDF (magic header present).</summary>
    public bool IsValidPdf { get; init; }

    /// <summary>true when the document is safe to accept.</summary>
    public bool IsAllowed { get; init; }

    /// <summary>Size of the uploaded file in bytes.</summary>
    public long SizeBytes { get; init; }

    /// <summary>Original file name (as uploaded), if provided.</summary>
    public string? FileName { get; init; }

    /// <summary>Short human-readable verdict.</summary>
    public string Summary { get; init; } = "";

    /// <summary>Human-readable reasons why the file was rejected.</summary>
    public IReadOnlyList<string> Reasons { get; init; } = [];

    /// <summary>Structured list of every dangerous construct detected.</summary>
    public IReadOnlyList<PdfFinding> Findings { get; init; } = [];

    public static PdfValidationResult Ok(string? fileName, long size, string summary) => new()
    {
        IsValidPdf = true,
        IsAllowed = true,
        SizeBytes = size,
        FileName = fileName,
        Summary = summary,
        Reasons = [],
        Findings = []
    };

    public static PdfValidationResult Rejected(
        bool validPdf,
        string? fileName,
        long size,
        string summary,
        IReadOnlyList<PdfFinding> findings)
    {
        var reasons = findings
            .Select(f => $"{f.Rule}: {f.Detail}")
            .Distinct()
            .ToList();

        if (reasons.Count == 0)
        {
            reasons.Add(summary);
        }

        return new PdfValidationResult
        {
            IsValidPdf = validPdf,
            IsAllowed = false,
            SizeBytes = size,
            FileName = fileName,
            Summary = summary,
            Reasons = reasons,
            Findings = findings
        };
    }
}
