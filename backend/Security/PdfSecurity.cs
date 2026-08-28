using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace PdfSecurityApi.Security;

/// <summary>
/// <para>
/// Static-free, injectable PDF scanner. It inspects the raw bytes of an uploaded PDF and
/// rejects anything that looks dangerous:
/// </para>
/// <list type="bullet">
///   <item>embedded JavaScript (Acrobat <c>/JS</c>, <c>app.*</c>, DOM script APIs),</item>
///   <item>external / dangerous links (<c>/URI</c>, <c>data:</c>, <c>javascript:</c>, <c>file:</c>, <c>http(s)://</c>),</item>
///   <item>OS command execution attempts (URI launch actions, Windows command paths),</item>
///   <item>embedded / attached files,</item>
///   <item>HTML / XSS injection smuggled inside annotations or <c>/FontMatrix</c>.</item>
/// </list>
/// <para>
/// It scans both the raw byte stream and the contents of any <c>FlateDecode</c> streams so that
/// hidden payloads are not missed when a generator compresses a dangerous dictionary.
/// </para>
/// </summary>
public sealed class PdfSecurity
{
    /// <summary>PDF magic header required at the start of a valid document.</summary>
    private const string PdfMagic = "%PDF-";

    private readonly PdfSecurityOptions _options;
    private readonly IReadOnlyList<PdfRule> _rules;

    public PdfSecurity(IOptions<PdfSecurityOptions>? options = null)
    {
        _options = options?.Value ?? new PdfSecurityOptions();
        _rules = BuildRules();
    }

    /// <summary>
    /// Validate an uploaded PDF. Returns <see cref="PdfValidationResult.IsAllowed"/> = false
    /// when the document is not a PDF, exceeds the size limit, or contains dangerous content.
    /// </summary>
    /// <param name="data">Raw file bytes (already read from the request stream).</param>
    /// <param name="fileName">Original file name for diagnostics.</param>
    public PdfValidationResult Validate(byte[] data, string? fileName = null)
    {
        long size = data?.LongLength ?? 0;

        if (data is null || data.Length == 0)
        {
            return PdfValidationResult.Rejected(false, fileName, size, "Empty upload.", [new PdfFinding("EmptyFile", "High", "The uploaded file is empty.")]);
        }

        if (size > _options.MaxFileSizeBytes)
        {
            return PdfValidationResult.Rejected(false, fileName, size,
                "File too large.",
                [new PdfFinding("FileTooLarge", "High", $"File is {size:N0} bytes; the maximum allowed size is {_options.MaxFileSizeBytes:N0} bytes.")]);
        }

        // 1. Basic PDF magic check.
        if (_options.RequirePdfHeader && !HasPdfMagic(data))
        {
            return PdfValidationResult.Rejected(false, fileName, size,
                "Not a valid PDF.",
                [new PdfFinding("MissingPdfHeader", "High", "The file does not start with the '%PDF-' header and is not a recognised PDF.")]);
        }

        // 2. Build the search corpus (raw + decompressed FlateDecode streams).
        var corpus = BuildScanCorpus(data);

        var findings = new List<PdfFinding>();
        foreach (var rule in _rules)
        {
            if (!IsRuleEnabled(rule))
            {
                continue;
            }

            AppendMatches(findings, rule, corpus);
        }

        // 3. If no dangerous constructs remain, the file is safe to keep.
        if (findings.Count == 0)
        {
            return PdfValidationResult.Ok(fileName, size, "The PDF is safe to accept.");
        }

        var summary = $"Blocked: {findings.Count} dangerous construct(s) detected.";
        return PdfValidationResult.Rejected(true, fileName, size, summary, findings);
    }

    // ---- Rule catalogue ---------------------------------------------------

    private readonly record struct PdfRule(string Name, string Title, string Severity, string Pattern, string Category);

    /// <summary>
    /// Every dangerous construct the scanner knows about. Each rule belongs to a category that maps to a
    /// toggle in <see cref="PdfSecurityOptions"/> (e.g. <see cref="PdfSecurityOptions.BlockJavaScript"/>).
    /// </summary>
    private static IReadOnlyList<PdfRule> BuildRules() =>
    [
        // Embedded JavaScript
        new("EmbeddedJavaScript", "Embedded JavaScript", "High", @"(?:/JS\s*\(|/JavaScript\s*\(|/JS\s*\()", "javascript"),
        new("AcrobatJavaScriptApi", "Acrobat JavaScript API", "High", @"app\s*\.\s*(?:alert|launchURL|openDoc|execMenuItem|exportDataObject|mailForm|goBack|openFDF|newDoc|media)\b", "javascript"),
        new("DomScriptExecution", "DOM script execution", "High", @"(?:document\s*\.\s*(?:write|cookie|createElement|getElementById|querySelector)\b|window\s*\.\s*(?:confirm|alert|open|eval)\b|console\s*\.\s*println\b)", "javascript"),
        new("ScriptFunctionCall", "Script function call", "High", @"\b(?:confirm|prompt|alert)\s*\(\s*", "javascript"),
        new("EvalOrFunction", "Dynamic code evaluation", "High", @"\beval\s*\(|new\s+Function\s*\(|\.constructor\s*=\s*null", "javascript"),
        new("XfaJavaScript", "XFA form scripting", "High", @"\b/XFA\b", "javascript"),
        new("OpenAction", "Open-action script trigger", "High", @"/OpenAction\b", "javascript"),

        // External / dangerous links
        new("DataUri", "Data: URI", "High", @"\bdata\s*:\s*text/", "links"),
        new("JavascriptUri", "javascript: URI", "High", @"\bjavascript\s*:\s*", "links"),
        new("VbscriptUri", "vbscript: URI", "High", @"\bvbscript\s*:\s*", "links"),
        new("FileUri", "file: URI", "High", @"\bfile\s*:\s*///*", "links"),
        new("UriAction", "External URI action", "Medium", @"(?:/URI\s*\(|\bURIAction\b|\b/SubmitForm\b|\b/ImportData\b)", "links"),
        new("ExternalHttpLink", "External http(s) link", "Medium", @"https?://", "links"),
        new("RemoteGoto", "Remote go-to link", "Medium", @"\b/GoToR\b|\b/GoToE\b", "links"),

        // Command execution
        new("WindowsCommandExecution", "Windows command", "High", @"\b(?:calc\.exe|cmd\.exe|cmd\.com|command\.com|powershell(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|wscript\.exe|cscript\.exe|certutil|regsvr32|bitsadmin|cmstp)\b", "commands"),
        new("CommandUri", "Command in URI", "High", @"\b(?:start|run)\b\s+[^\s]*(?:\.exe|\.com|\.bat|\.cmd|\.ps1)\b", "commands"),
        new("AbsoluteWindowsPath", "Windows path/command", "High", @"[A-Za-z]:/\\(?:Windows|System32|Program Files|Users|ProgramData)", "commands"),

        // Embedded / attached files
        new("EmbeddedFile", "Embedded file", "High", @"(?:/EmbeddedFile\b|/Filespec\b|/EF\b|/UF\b|/EmbeddedFiles\b)", "embedded"),
        new("LaunchAction", "Launch action", "High", @"(?:/Launch\b|/S\s*/Launch\b)", "embedded"),

        // HTML / XSS injection inside annotations
        new("HtmlInjection", "HTML/script injection", "High", @"(?:</?script\b|</?iframe\b|<svg\b|<details\b|<img\b)", "annotations"),
        new("EventHandlerInjection", "Event-handler injection", "High", @"\bon(?:toggle|load|error|mouseover|click|focus|mouseenter|input|change|open|close)\s*=\s*(?:confirm|alert|prompt|eval|document|window)", "annotations"),
        new("AnnotationPayload", "Annotation injection", "High", @"(?:'|"")\s*>\s*'?\s*>\s*<\s*(?:details|div|iframe|svg|img|script)", "annotations"),

        // FontMatrix JS injection (e.g. PDF.js CVE-2024-4367 PoC)
        new("FontMatrixInjection", "FontMatrix injection", "High", @"\/FontMatrix\b[^\]]{0,600}?\([^)]{0,200}?\)\s*;", "annotations"),
    ];

    private bool IsRuleEnabled(PdfRule rule) => rule.Category switch
    {
        "javascript" => _options.BlockJavaScript,
        "links" => _options.BlockExternalLinks,
        "commands" => _options.BlockCommandExecution,
        "embedded" => _options.BlockEmbeddedFiles,
        "annotations" => _options.BlockAnnotationInjection,
        _ => true
    };

    // ---- Matching ----------------------------------------------------------

    private static void AppendMatches(List<PdfFinding> findings, PdfRule rule, string corpus)
    {
        Regex regex;
        try
        {
            regex = new Regex(rule.Pattern,
                RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant,
                TimeSpan.FromMilliseconds(300));
        }
        catch
        {
            return; // A bad pattern must never break validation.
        }

        int count = 0;
        try
        {
            foreach (Match m in regex.Matches(corpus))
            {
                var sample = Collapse(m.Value);
                findings.Add(new PdfFinding(rule.Title, rule.Severity, $"Found dangerous construct in PDF content — \"{sample}\"."));

                if (++count >= 5)
                {
                    break; // Do not blow up the response for a single highly-repeated construct.
                }
            }
        }
        catch (RegexMatchTimeoutException)
        {
            findings.Add(new PdfFinding(rule.Title, rule.Severity, $"Rule deadlined while scanning (pattern '{rule.Pattern}')."));
        }
    }

    private static string Collapse(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "";
        }

        value = Regex.Replace(value, @"\s+", " ").Trim();
        return value.Length <= 90 ? value : value[..90] + "…";
    }

    // ---- Corpus construction ----------------------------------------------

    private string BuildScanCorpus(byte[] data)
    {
        var sb = new StringBuilder(data.Length + (data.Length / 2));
        sb.Append(Latin1(data.AsSpan()));

        AppendInflatedStreams(data, sb);
        return sb.ToString();
    }

    /// <summary>Latin-1 mapping keeps every byte value 1:1, so regexes see exact raw bytes regardless of encoding.</summary>
    private static string Latin1(ReadOnlySpan<byte> bytes) => Encoding.Latin1.GetString(bytes);

    private void AppendInflatedStreams(byte[] data, StringBuilder corpus)
    {
        var text = Latin1(data.AsSpan());
        int searchFrom = 0;

        while (searchFrom < data.Length)
        {
            int streamIdx = text.IndexOf("stream", searchFrom, StringComparison.Ordinal);
            if (streamIdx < 0)
            {
                break;
            }

            int endIdx = text.IndexOf("endstream", streamIdx, StringComparison.Ordinal);
            if (endIdx < 0)
            {
                break;
            }

            // Only decompress regions that declared a FlateDecode filter.
            int headerStart = Math.Max(0, streamIdx - 512);
            var header = text.Substring(headerStart, streamIdx - headerStart);
            bool isFlate = header.Contains("FlateDecode", StringComparison.OrdinalIgnoreCase);

            int dataStart = streamIdx + "stream".Length;
            while (dataStart < endIdx && (data[dataStart] == (byte)'\r' || data[dataStart] == (byte)'\n'))
            {
                dataStart++;
            }

            int dataEnd = endIdx;
            while (dataEnd > dataStart && (data[dataEnd - 1] == (byte)'\r' || data[dataEnd - 1] == (byte)'\n'))
            {
                dataEnd--;
            }

            if (isFlate && dataEnd > dataStart)
            {
                if (TryInflate(data, dataStart, dataEnd) is { } inflated)
                {
                    corpus.Append(inflated);
                }
            }

            searchFrom = endIdx + "endstream".Length;
        }
    }

    private string? TryInflate(byte[] data, int start, int end)
    {
        try
        {
            using var input = new MemoryStream(data, start, end - start, writable: false);
            using var zlib = new ZLibStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();

            var buffer = new byte[8192];
            int total = 0;
            int read;
            while ((read = zlib.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, read);
                total += read;
                if (total > _options.MaxInflateBytes)
                {
                    break;
                }
            }

            // Decoded content must not temporarily hold more than the configured cap.
            if (output.Length > _options.MaxInflateBytes)
            {
                return null;
            }

            return Latin1(output.ToArray());
        }
        catch
        {
            return null; // Not actually a FlateDecode stream (or corrupt) — ignore.
        }
    }

    private bool HasPdfMagic(byte[] data)
    {
        int scan = Math.Min(data.Length, Math.Max(1, _options.HeaderScanBytes));
        var head = Latin1(data.AsSpan(0, scan));
        return head.Contains(PdfMagic, StringComparison.Ordinal);
    }
}
