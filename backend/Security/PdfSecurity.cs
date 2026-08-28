using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace PdfSecurityApi.Security;

/// <summary>
/// Performs bounded, fail-closed inspection of PDF syntax and decoded general-purpose streams.
/// This is a policy gate, not a guarantee that a PDF viewer has no parser vulnerabilities.
/// </summary>
public sealed class PdfSecurity
{
    private const string PdfMagic = "%PDF-";
    private readonly PdfSecurityOptions _options;
    private readonly IReadOnlyList<PdfRule> _rules;

    public PdfSecurity(IOptions<PdfSecurityOptions>? options = null)
    {
        _options = options?.Value ?? new PdfSecurityOptions();
        _rules = BuildRules();
    }

    public PdfValidationResult Validate(byte[] data, string? fileName = null) =>
        Validate(data, data?.Length ?? 0, fileName, CancellationToken.None);

    /// <summary>Validate a populated prefix of a byte buffer without another full-size copy.</summary>
    public PdfValidationResult Validate(
        byte[] data,
        int length,
        string? fileName = null,
        CancellationToken cancellationToken = default)
    {
        long size = length;
        if (data is null || length <= 0 || length > data.Length)
        {
            return PdfValidationResult.Rejected(false, fileName, Math.Max(0, size), "Empty or invalid upload.",
                [new PdfFinding("InvalidFile", "High", "The uploaded byte buffer is empty or invalid.")]);
        }

        if (size > _options.MaxFileSizeBytes)
        {
            return PdfValidationResult.Rejected(false, fileName, size, "File too large.",
                [new PdfFinding("FileTooLarge", "High",
                    $"File is {size:N0} bytes; the maximum is {_options.MaxFileSizeBytes:N0} bytes.")]);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var bytes = data.AsSpan(0, length);
        bool hasHeader = HasPdfMagic(bytes);
        if (_options.RequirePdfHeader && !hasHeader)
        {
            return PdfValidationResult.Rejected(false, fileName, size, "Not a valid PDF.",
                [new PdfFinding("MissingPdfHeader", "High", "A valid PDF version header was not found.")]);
        }

        var corpusResult = BuildScanCorpus(data, length, cancellationToken);
        var findings = corpusResult.Findings;
        bool structurallyValid = hasHeader && ValidateStructure(bytes, corpusResult.Corpus, findings);

        foreach (var rule in _rules)
        {
            if (findings.Count >= _options.MaxFindings)
            {
                break;
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (IsRuleEnabled(rule))
            {
                AppendMatches(findings, rule, corpusResult.Corpus);
            }
        }

        if (findings.Count == 0 && structurallyValid)
        {
            return PdfValidationResult.Ok(fileName, size,
                "No configured dangerous constructs were detected.");
        }

        var summary = structurallyValid
            ? $"Blocked: {findings.Count} dangerous or unscannable construct(s) detected."
            : "Rejected: the upload is not a structurally valid, fully scannable PDF.";
        return PdfValidationResult.Rejected(structurallyValid, fileName, size, summary, findings);
    }

    private readonly record struct PdfRule(string Title, string Severity, Regex Regex, string Category);

    private static IReadOnlyList<PdfRule> BuildRules() =>
    [
        Rule("JavaScript action", "High", @"(?:/S\s*/JavaScript\b|/JavaScript\b|/JS\b)", "javascript"),
        Rule("Acrobat JavaScript API", "High", @"app\s*\.\s*(?:alert|launchURL|openDoc|execMenuItem|exportDataObject|mailForm|goBack|openFDF|newDoc|media)\b", "javascript"),
        Rule("DOM script execution", "High", @"(?:document\s*\.\s*(?:write|cookie|createElement|getElementById|querySelector)\b|window\s*\.\s*(?:confirm|alert|open|eval)\b|console\s*\.\s*println\b)", "javascript"),
        Rule("Script function call", "High", @"\b(?:confirm|prompt|alert)\s*\(", "javascript"),
        Rule("Dynamic code evaluation", "High", @"\beval\s*\(|new\s+Function\s*\(|\.constructor\s*=\s*null", "javascript"),
        Rule("XFA form", "High", @"/XFA\b", "javascript"),

        Rule("Data URI", "High", @"\bdata\s*:\s*text/", "links"),
        Rule("JavaScript URI", "High", @"\bjavascript\s*:\s*", "links"),
        Rule("VBScript URI", "High", @"\bvbscript\s*:\s*", "links"),
        Rule("File URI", "High", @"\bfile\s*:\s*///?", "links"),
        Rule("External URI action", "Medium", @"(?:/URI\b|/SubmitForm\b|/ImportData\b)", "links"),
        Rule("External HTTP link", "Medium", @"https?://", "links"),
        Rule("Remote go-to link", "Medium", @"/(?:GoToR|GoToE)\b", "links"),

        Rule("Windows command", "High", @"\b(?:calc\.exe|cmd\.exe|cmd\.com|command\.com|powershell(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|wscript\.exe|cscript\.exe|certutil|regsvr32|bitsadmin|cmstp)\b", "commands"),
        Rule("Command URI", "High", @"\b(?:start|run)\b\s+[^\s]*(?:\.exe|\.com|\.bat|\.cmd|\.ps1)\b", "commands"),
        Rule("Windows path", "High", @"[A-Za-z]:[/\\](?:Windows|System32|Program Files|Users|ProgramData)\b", "commands"),

        Rule("Embedded file", "High", @"/(?:EmbeddedFile|Filespec|EF|UF|EmbeddedFiles|Collection)\b", "embedded"),
        Rule("Launch action", "High", @"(?:/Launch\b|/S\s*/Launch\b)", "embedded"),
        Rule("Active multimedia", "High", @"/(?:RichMedia|Movie|Sound|Rendition|3D)\b", "embedded"),

        Rule("HTML/script injection", "High", @"(?:</?script\b|</?iframe\b|<svg\b|<details\b|<img\b)", "annotations"),
        Rule("Event-handler injection", "High", @"\bon(?:toggle|load|error|mouseover|click|focus|mouseenter|input|change|open|close)\s*=", "annotations"),
        Rule("FontMatrix injection", "High", @"/FontMatrix\b[^\]]{0,600}?\([^)]{0,200}?\)\s*;", "annotations")
    ];

    private static PdfRule Rule(string title, string severity, string pattern, string category) =>
        new(title, severity,
            new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant,
                TimeSpan.FromMilliseconds(250)), category);

    private bool IsRuleEnabled(PdfRule rule) => rule.Category switch
    {
        "javascript" => _options.BlockJavaScript,
        "links" => _options.BlockExternalLinks,
        "commands" => _options.BlockCommandExecution,
        "embedded" => _options.BlockEmbeddedFiles,
        "annotations" => _options.BlockAnnotationInjection,
        _ => true
    };

    private void AppendMatches(List<PdfFinding> findings, PdfRule rule, string corpus)
    {
        try
        {
            int count = 0;
            foreach (Match match in rule.Regex.Matches(corpus))
            {
                findings.Add(new PdfFinding(rule.Title, rule.Severity,
                    $"Found disallowed PDF content — \"{Collapse(match.Value)}\"."));
                if (++count >= 5 || findings.Count >= _options.MaxFindings)
                {
                    break;
                }
            }
        }
        catch (RegexMatchTimeoutException)
        {
            findings.Add(new PdfFinding("ScanTimeout", "High",
                $"The {rule.Title} rule exceeded its processing deadline."));
        }
    }

    private static string Collapse(string value)
    {
        value = Regex.Replace(value, @"\s+", " ").Trim();
        return value.Length <= 90 ? value : value[..90] + "…";
    }

    private sealed record CorpusResult(string Corpus, List<PdfFinding> Findings);

    private CorpusResult BuildScanCorpus(byte[] data, int length, CancellationToken cancellationToken)
    {
        var findings = new List<PdfFinding>();
        int maxCorpusChars = checked((int)Math.Min(int.MaxValue,
            _options.MaxFileSizeBytes + _options.MaxTotalInflateBytes + 4L * 1024 * 1024));
        var corpus = new BoundedCorpus(maxCorpusChars);

        try
        {
            AppendSegment(corpus, data.AsSpan(0, length));
            AppendDecodedStreams(data, length, corpus, findings, cancellationToken);
        }
        catch (PdfScanException exception)
        {
            findings.Add(new PdfFinding(exception.Rule, "High", exception.Message));
        }

        return new CorpusResult(corpus.ToString(), findings);
    }

    private static void AppendSegment(BoundedCorpus corpus, ReadOnlySpan<byte> bytes)
    {
        var normalized = NormalizeNameEscapes(Encoding.Latin1.GetString(bytes));
        corpus.Append(normalized);
        AppendDecodedStrings(normalized, corpus);
    }

    private void AppendDecodedStreams(
        byte[] data,
        int length,
        BoundedCorpus corpus,
        List<PdfFinding> findings,
        CancellationToken cancellationToken)
    {
        var rawText = Encoding.Latin1.GetString(data, 0, length);
        int searchFrom = 0;
        int streamCount = 0;
        int totalDecoded = 0;

        while (searchFrom < length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int streamIndex = FindStreamToken(rawText, searchFrom);
            if (streamIndex < 0)
            {
                break;
            }

            if (++streamCount > _options.MaxStreamCount)
            {
                throw new PdfScanException("TooManyStreams",
                    $"The PDF contains more than {_options.MaxStreamCount} stream objects.");
            }

            int endIndex = rawText.IndexOf("endstream", streamIndex + 6, StringComparison.Ordinal);
            if (endIndex < 0)
            {
                AddUnscannable(findings, streamCount, "The stream has no endstream marker.");
                break;
            }

            int dataStart = streamIndex + 6;
            if (dataStart < endIndex && data[dataStart] == '\r') dataStart++;
            if (dataStart < endIndex && data[dataStart] == '\n') dataStart++;
            int dataEnd = endIndex;
            if (dataEnd > dataStart && data[dataEnd - 1] == '\n') dataEnd--;
            if (dataEnd > dataStart && data[dataEnd - 1] == '\r') dataEnd--;

            int dictionaryStart = rawText.LastIndexOf("<<", streamIndex, StringComparison.Ordinal);
            string header = dictionaryStart >= 0 && streamIndex - dictionaryStart <= 8192
                ? NormalizeNameEscapes(rawText[dictionaryStart..streamIndex])
                : string.Empty;

            var filters = ExtractFilters(header);
            if (filters is null)
            {
                AddUnscannable(findings, streamCount, "The stream filter is indirect or malformed.");
            }
            else if (filters.Count > 0 && !IsOpaqueImageStream(header, filters))
            {
                try
                {
                    var decoded = DecodeFilters(data.AsSpan(dataStart, dataEnd - dataStart), filters,
                        ref totalDecoded, cancellationToken);
                    AppendSegment(corpus, decoded);
                }
                catch (Exception exception) when (exception is InvalidDataException or PdfScanException)
                {
                    AddUnscannable(findings, streamCount, exception.Message);
                }
            }

            searchFrom = endIndex + "endstream".Length;
        }
    }

    private void AddUnscannable(List<PdfFinding> findings, int streamNumber, string detail)
    {
        if (_options.RejectUnscannableStreams && findings.Count < _options.MaxFindings)
        {
            findings.Add(new PdfFinding("UnscannableStream", "High",
                $"Stream {streamNumber} could not be inspected safely: {detail}"));
        }
    }

    private static int FindStreamToken(string text, int start)
    {
        while (start < text.Length)
        {
            int index = text.IndexOf("stream", start, StringComparison.Ordinal);
            if (index < 0) return -1;
            bool before = index == 0 || IsPdfDelimiterOrWhiteSpace(text[index - 1]);
            int afterIndex = index + 6;
            bool after = afterIndex < text.Length && text[afterIndex] is '\r' or '\n';
            if (before && after) return index;
            start = index + 6;
        }
        return -1;
    }

    private static List<string>? ExtractFilters(string header)
    {
        int index = header.LastIndexOf("/Filter", StringComparison.Ordinal);
        if (index < 0) return [];
        index += "/Filter".Length;
        while (index < header.Length && char.IsWhiteSpace(header[index])) index++;
        if (index >= header.Length) return null;

        string filterText;
        if (header[index] == '[')
        {
            int end = header.IndexOf(']', index + 1);
            if (end < 0 || end - index > 1024) return null;
            filterText = header[(index + 1)..end];
        }
        else if (header[index] == '/')
        {
            int end = index + 1;
            while (end < header.Length && !IsPdfDelimiterOrWhiteSpace(header[end])) end++;
            filterText = header[index..end];
        }
        else
        {
            return null;
        }

        return Regex.Matches(filterText, @"/([A-Za-z0-9]+)")
            .Select(match => match.Groups[1].Value)
            .ToList();
    }

    private static bool IsOpaqueImageStream(string header, IReadOnlyList<string> filters) =>
        filters.Count > 0 && Regex.IsMatch(header, @"/Subtype\s*/Image\b", RegexOptions.CultureInvariant);

    private byte[] DecodeFilters(
        ReadOnlySpan<byte> encoded,
        IReadOnlyList<string> filters,
        ref int totalDecoded,
        CancellationToken cancellationToken)
    {
        byte[] current = encoded.ToArray();
        foreach (string filter in filters)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int inputLength = current.Length;
            current = filter switch
            {
                "FlateDecode" or "Fl" => Inflate(current, cancellationToken),
                "ASCIIHexDecode" or "AHx" => DecodeAsciiHex(current),
                "ASCII85Decode" or "A85" => DecodeAscii85(current),
                "RunLengthDecode" or "RL" => DecodeRunLength(current),
                _ => throw new InvalidDataException($"Unsupported stream filter /{filter}.")
            };

            if (current.Length > _options.MaxInflateBytes)
            {
                throw new PdfScanException("InflateLimitExceeded",
                    $"Decoded stream exceeds {_options.MaxInflateBytes:N0} bytes.");
            }
            if (current.Length > Math.Max(1024L, inputLength) * _options.MaxCompressionRatio)
            {
                throw new PdfScanException("CompressionRatioExceeded",
                    $"Decoded stream exceeds the {_options.MaxCompressionRatio}:1 expansion limit.");
            }

            totalDecoded = checked(totalDecoded + current.Length);
            if (totalDecoded > _options.MaxTotalInflateBytes)
            {
                throw new PdfScanException("TotalInflateLimitExceeded",
                    $"Decoded streams exceed the {_options.MaxTotalInflateBytes:N0}-byte document limit.");
            }
        }
        return current;
    }

    private byte[] Inflate(byte[] input, CancellationToken cancellationToken)
    {
        using var source = new MemoryStream(input, writable: false);
        using var zlib = new ZLibStream(source, CompressionMode.Decompress);
        using var output = new MemoryStream(Math.Min(_options.MaxInflateBytes, 64 * 1024));
        var buffer = new byte[8192];
        int read;
        while ((read = zlib.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (output.Length + read > _options.MaxInflateBytes)
            {
                throw new PdfScanException("InflateLimitExceeded",
                    $"Decoded stream exceeds {_options.MaxInflateBytes:N0} bytes.");
            }
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static byte[] DecodeAsciiHex(ReadOnlySpan<byte> input)
    {
        using var output = new MemoryStream(input.Length / 2);
        int high = -1;
        foreach (byte value in input)
        {
            if (char.IsWhiteSpace((char)value)) continue;
            if (value == '>') break;
            int nibble = HexValue((char)value);
            if (nibble < 0) throw new InvalidDataException("Invalid ASCIIHex stream data.");
            if (high < 0) high = nibble;
            else { output.WriteByte((byte)((high << 4) | nibble)); high = -1; }
        }
        if (high >= 0) output.WriteByte((byte)(high << 4));
        return output.ToArray();
    }

    private static byte[] DecodeAscii85(ReadOnlySpan<byte> input)
    {
        using var output = new MemoryStream(input.Length);
        Span<byte> group = stackalloc byte[5];
        int count = 0;
        foreach (byte value in input)
        {
            if (char.IsWhiteSpace((char)value) || value == (byte)'<' || value == (byte)'>') continue;
            if (value == '~') break;
            if (value == 'z')
            {
                if (count != 0) throw new InvalidDataException("Invalid ASCII85 z shorthand.");
                output.Write([0, 0, 0, 0]);
                continue;
            }
            if (value is < 33 or > 117) throw new InvalidDataException("Invalid ASCII85 stream data.");
            group[count++] = value;
            if (count == 5) { WriteAscii85Group(output, group, 4); count = 0; }
        }
        if (count == 1) throw new InvalidDataException("Invalid final ASCII85 group.");
        if (count > 1)
        {
            int outputCount = count - 1;
            while (count < 5) group[count++] = (byte)'u';
            WriteAscii85Group(output, group, outputCount);
        }
        return output.ToArray();
    }

    private static void WriteAscii85Group(Stream output, ReadOnlySpan<byte> group, int outputCount)
    {
        ulong number = 0;
        for (int index = 0; index < 5; index++) number = number * 85 + (uint)(group[index] - 33);
        if (number > uint.MaxValue) throw new InvalidDataException("ASCII85 group overflow.");
        uint value = (uint)number;
        Span<byte> bytes = stackalloc byte[4]
        {
            (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value
        };
        output.Write(bytes[..outputCount]);
    }

    private static byte[] DecodeRunLength(ReadOnlySpan<byte> input)
    {
        using var output = new MemoryStream(input.Length);
        int index = 0;
        while (index < input.Length)
        {
            int length = input[index++];
            if (length == 128) break;
            if (length <= 127)
            {
                int count = length + 1;
                if (index + count > input.Length) throw new InvalidDataException("Truncated RunLength stream.");
                output.Write(input.Slice(index, count));
                index += count;
            }
            else
            {
                if (index >= input.Length) throw new InvalidDataException("Truncated RunLength stream.");
                byte value = input[index++];
                for (int repeat = 0; repeat < 257 - length; repeat++) output.WriteByte(value);
            }
        }
        return output.ToArray();
    }

    private bool ValidateStructure(ReadOnlySpan<byte> data, string corpus, List<PdfFinding> findings)
    {
        bool valid = true;
        if (_options.RequirePdfStructure)
        {
            int tailLength = Math.Min(data.Length, 4096);
            string tail = Encoding.Latin1.GetString(data[^tailLength..]);
            valid &= Require(tail.Contains("%%EOF", StringComparison.Ordinal), findings,
                "MissingEofMarker", "The PDF has no EOF marker near the end of the file.");
            valid &= Require(corpus.Contains("/Catalog", StringComparison.Ordinal), findings,
                "MissingCatalog", "The PDF catalog was not found.");
            valid &= Require(corpus.Contains("/Pages", StringComparison.Ordinal), findings,
                "MissingPageTree", "The PDF page tree was not found.");
            valid &= Require(corpus.Contains("startxref", StringComparison.Ordinal), findings,
                "MissingCrossReference", "The PDF has no startxref marker.");
        }

        if (_options.RejectEncryptedPdf && Regex.IsMatch(corpus, @"/Encrypt\b", RegexOptions.CultureInvariant))
        {
            findings.Add(new PdfFinding("EncryptedPdf", "High",
                "Encrypted PDF strings and streams cannot be inspected without decryption."));
            valid = false;
        }

        return valid && findings.All(finding =>
            finding.Rule is not ("UnscannableStream" or "ScanBudgetExceeded" or "InflateLimitExceeded"));
    }

    private static bool Require(bool condition, List<PdfFinding> findings, string rule, string detail)
    {
        if (!condition) findings.Add(new PdfFinding(rule, "High", detail));
        return condition;
    }

    private bool HasPdfMagic(ReadOnlySpan<byte> data)
    {
        int scanLength = Math.Min(data.Length, Math.Max(1, _options.HeaderScanBytes));
        string header = Encoding.Latin1.GetString(data[..scanLength]);
        int index = header.IndexOf(PdfMagic, StringComparison.Ordinal);
        return index >= 0 && index + 8 <= header.Length &&
               header[index + 5] is '1' or '2' && header[index + 6] == '.' && char.IsAsciiDigit(header[index + 7]);
    }

    private static string NormalizeNameEscapes(string text)
    {
        var output = new StringBuilder(text.Length);
        for (int index = 0; index < text.Length; index++)
        {
            char current = text[index];
            output.Append(current);
            if (current != '/') continue;

            while (++index < text.Length && !IsPdfDelimiterOrWhiteSpace(text[index]))
            {
                if (text[index] == '#' && index + 2 < text.Length)
                {
                    int high = HexValue(text[index + 1]);
                    int low = HexValue(text[index + 2]);
                    if (high >= 0 && low >= 0)
                    {
                        output.Append((char)((high << 4) | low));
                        index += 2;
                        continue;
                    }
                }
                output.Append(text[index]);
            }
            if (index < text.Length) output.Append(text[index]);
        }
        return output.ToString();
    }

    private static void AppendDecodedStrings(string text, BoundedCorpus corpus)
    {
        for (int index = 0; index < text.Length; index++)
        {
            if (text[index] == '<' && (index + 1 >= text.Length || text[index + 1] != '<'))
            {
                var decoded = new StringBuilder();
                int high = -1;
                int cursor = index + 1;
                bool valid = false;
                for (; cursor < text.Length; cursor++)
                {
                    char value = text[cursor];
                    if (value == '>') { valid = true; break; }
                    if (char.IsWhiteSpace(value)) continue;
                    int nibble = HexValue(value);
                    if (nibble < 0) break;
                    if (high < 0) high = nibble;
                    else { decoded.Append((char)((high << 4) | nibble)); high = -1; }
                }
                if (valid)
                {
                    if (high >= 0) decoded.Append((char)(high << 4));
                    corpus.Append("\n");
                    corpus.Append(NormalizeNameEscapes(decoded.ToString()));
                    corpus.Append("\n");
                    index = cursor;
                }
            }
            else if (text[index] == '(')
            {
                var decoded = new StringBuilder();
                int depth = 1;
                int cursor = index + 1;
                for (; cursor < text.Length && depth > 0; cursor++)
                {
                    char value = text[cursor];
                    if (value == '\\' && cursor + 1 < text.Length)
                    {
                        char escaped = text[++cursor];
                        if (escaped == '\r') { if (cursor + 1 < text.Length && text[cursor + 1] == '\n') cursor++; continue; }
                        if (escaped == '\n') continue;
                        if (escaped is >= '0' and <= '7')
                        {
                            int octal = escaped - '0';
                            int digits = 1;
                            while (digits < 3 && cursor + 1 < text.Length && text[cursor + 1] is >= '0' and <= '7')
                            {
                                octal = octal * 8 + text[++cursor] - '0';
                                digits++;
                            }
                            decoded.Append((char)(octal & 0xff));
                            continue;
                        }
                        decoded.Append(escaped switch
                        {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            'b' => '\b',
                            'f' => '\f',
                            _ => escaped
                        });
                    }
                    else if (value == '(') { depth++; decoded.Append(value); }
                    else if (value == ')') { if (--depth > 0) decoded.Append(value); }
                    else decoded.Append(value);
                }
                if (depth == 0)
                {
                    corpus.Append("\n");
                    corpus.Append(NormalizeNameEscapes(decoded.ToString()));
                    corpus.Append("\n");
                    index = cursor - 1;
                }
            }
        }
    }

    private static bool IsPdfDelimiterOrWhiteSpace(char value) =>
        char.IsWhiteSpace(value) || value is '(' or ')' or '<' or '>' or '[' or ']' or '{' or '}' or '/' or '%';

    private static int HexValue(char value) => value switch
    {
        >= '0' and <= '9' => value - '0',
        >= 'a' and <= 'f' => value - 'a' + 10,
        >= 'A' and <= 'F' => value - 'A' + 10,
        _ => -1
    };

    private sealed class BoundedCorpus(int maxChars)
    {
        private readonly StringBuilder _builder = new(Math.Min(maxChars, 1024 * 1024));

        public void Append(string value)
        {
            if ((long)_builder.Length + value.Length > maxChars)
            {
                throw new PdfScanException("ScanBudgetExceeded",
                    $"The normalized PDF content exceeds the {maxChars:N0}-character scan budget.");
            }
            _builder.Append(value);
        }

        public override string ToString() => _builder.ToString();
    }

    private sealed class PdfScanException(string rule, string message) : Exception(message)
    {
        public string Rule { get; } = rule;
    }
}
