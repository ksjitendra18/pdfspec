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

    /// <summary>Number of leading bytes to scan for the "%PDF-" magic header.</summary>
    public int HeaderScanBytes { get; set; } = 1024;
}
