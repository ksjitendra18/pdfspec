namespace PdfSecurityApi.Security;

/// <summary>
/// Configuration for <see cref="PdfSecurity"/>. Bound from the "PdfSecurity" configuration
/// section so the rules can be tuned per environment without a code change.
/// </summary>
public sealed class PdfSecurityOptions
{
    /// <summary>Maximum accepted upload size in bytes. Larger files are rejected outright.</summary>
    public long MaxFileSizeBytes { get; set; } = 10 * 1024 * 1024;

    /// <summary>Cap on how many decompressed bytes we inspect per FlateDecode stream.</summary>
    public int MaxInflateBytes { get; set; } = 2 * 1024 * 1024;

    /// <summary>Maximum decoded bytes across all streams in one document.</summary>
    public int MaxTotalInflateBytes { get; set; } = 8 * 1024 * 1024;

    /// <summary>Maximum number of stream objects inspected in one document.</summary>
    public int MaxStreamCount { get; set; } = 256;

    /// <summary>Maximum permitted expansion ratio for a decoded stream.</summary>
    public int MaxCompressionRatio { get; set; } = 200;

    /// <summary>Maximum number of findings returned for one document.</summary>
    public int MaxFindings { get; set; } = 100;

    /// <summary>Reject files containing scripts (Acrobat /JavaScript, app.*, DOM script APIs...).</summary>
    public bool BlockJavaScript { get; set; } = true;

    /// <summary>Reject files containing external / dangerous links (URI actions, data:, javascript:, http(s)...).</summary>
    public bool BlockExternalLinks { get; set; } = true;

    /// <summary>Reject files carrying embedded / attached files.</summary>
    public bool BlockEmbeddedFiles { get; set; } = true;

    /// <summary>Reject files attempting OS command execution via URI / launch actions.</summary>
    public bool BlockCommandExecution { get; set; } = true;

    /// <summary>Reject files with HTML/JS injection inside annotations (ontoggle, script, iframe...).</summary>
    public bool BlockAnnotationInjection { get; set; } = true;

    /// <summary>Require a PDF magic header before inspecting the document.</summary>
    public bool RequirePdfHeader { get; set; } = true;

    /// <summary>Require a trailer EOF marker and basic catalog/page-tree structure.</summary>
    public bool RequirePdfStructure { get; set; } = true;

    /// <summary>Reject encrypted PDFs because their strings and streams cannot be inspected.</summary>
    public bool RejectEncryptedPdf { get; set; } = true;

    /// <summary>Reject a filtered stream when it cannot be decoded safely.</summary>
    public bool RejectUnscannableStreams { get; set; } = true;

    /// <summary>Number of leading bytes to scan for the "%PDF-" magic header.</summary>
    public int HeaderScanBytes { get; set; } = 1024;
}
