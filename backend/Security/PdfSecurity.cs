using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
#if !NETFRAMEWORK
using Microsoft.Extensions.Options;
#endif

// Nullable reference annotations do not exist in the C# 7.3 build used for net472.
#pragma warning disable CS8625, CS8603, CS8600, CS8604

namespace PdfSecurityApi.Security
{
    /// <summary>
    /// Performs bounded, fail-closed inspection of PDF syntax and decoded general-purpose streams.
    /// Compatible with .NET Framework 4.7.2 and modern .NET.
    /// </summary>
    public sealed class PdfSecurity
    {
        private const string PdfMagic = "%PDF-";
        private static readonly Encoding PdfEncoding = Encoding.GetEncoding(28591);
        private readonly PdfSecurityOptions _options;
        private readonly IReadOnlyList<PdfRule> _rules;

        public PdfSecurity() : this((PdfSecurityOptions)null) { }

        public PdfSecurity(PdfSecurityOptions options)
        {
            _options = options ?? new PdfSecurityOptions();
            _rules = BuildRules();
        }

#if !NETFRAMEWORK
        /// <summary>Supports options injection in the ASP.NET Core application.</summary>
        public PdfSecurity(IOptions<PdfSecurityOptions> options)
            : this(options == null ? null : options.Value)
        {
        }
#endif

        public PdfValidationResult Validate(byte[] data, string fileName = null)
        {
            return Validate(data, data == null ? 0 : data.Length, fileName, CancellationToken.None);
        }

        public PdfValidationResult Validate(byte[] data, int length, string fileName = null,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            long size = length;
            if (data == null || length <= 0 || length > data.Length)
                return PdfValidationResult.Rejected(false, fileName, Math.Max(0, size), "Empty or invalid upload.",
                    new[] { new PdfFinding("InvalidFile", "High", "The uploaded byte buffer is empty or invalid.") });

            if (size > _options.MaxFileSizeBytes)
                return PdfValidationResult.Rejected(false, fileName, size, "File too large.", new[]
                {
                    new PdfFinding("FileTooLarge", "High", string.Format(
                        "File is {0:N0} bytes; the maximum is {1:N0} bytes.", size, _options.MaxFileSizeBytes))
                });

            cancellationToken.ThrowIfCancellationRequested();
            bool hasHeader = HasPdfMagic(data, length);
            if (_options.RequirePdfHeader && !hasHeader)
                return PdfValidationResult.Rejected(false, fileName, size, "Not a valid PDF.",
                    new[] { new PdfFinding("MissingPdfHeader", "High", "A valid PDF version header was not found.") });

            CorpusResult corpusResult = BuildScanCorpus(data, length, cancellationToken);
            List<PdfFinding> findings = corpusResult.Findings;
            bool structurallyValid = hasHeader && ValidateStructure(data, length, corpusResult.Corpus, findings);

            foreach (PdfRule rule in _rules)
            {
                if (findings.Count >= _options.MaxFindings) break;
                cancellationToken.ThrowIfCancellationRequested();
                if (IsRuleEnabled(rule)) AppendMatches(findings, rule, corpusResult.Corpus);
            }

            if (findings.Count == 0 && structurallyValid)
                return PdfValidationResult.Ok(fileName, size, "No configured dangerous constructs were detected.");

            string summary = structurallyValid
                ? string.Format("Blocked: {0} dangerous or unscannable construct(s) detected.", findings.Count)
                : "Rejected: the upload is not a structurally valid, fully scannable PDF.";
            return PdfValidationResult.Rejected(structurallyValid, fileName, size, summary, findings);
        }

        private sealed class PdfRule
        {
            public PdfRule(string title, string severity, Regex regex, string category)
            { Title = title; Severity = severity; Regex = regex; Category = category; }
            public string Title { get; private set; }
            public string Severity { get; private set; }
            public Regex Regex { get; private set; }
            public string Category { get; private set; }
        }

        private static IReadOnlyList<PdfRule> BuildRules()
        {
            return new[]
            {
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
            };
        }

        private static PdfRule Rule(string title, string severity, string pattern, string category)
        {
            return new PdfRule(title, severity, new Regex(pattern,
                RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant,
                TimeSpan.FromMilliseconds(250)), category);
        }

        private bool IsRuleEnabled(PdfRule rule)
        {
            switch (rule.Category)
            {
                case "javascript": return _options.BlockJavaScript;
                case "links": return _options.BlockExternalLinks;
                case "commands": return _options.BlockCommandExecution;
                case "embedded": return _options.BlockEmbeddedFiles;
                case "annotations": return _options.BlockAnnotationInjection;
                default: return true;
            }
        }

        private void AppendMatches(List<PdfFinding> findings, PdfRule rule, string corpus)
        {
            try
            {
                int count = 0;
                foreach (Match match in rule.Regex.Matches(corpus))
                {
                    findings.Add(new PdfFinding(rule.Title, rule.Severity, string.Format(
                        "Found disallowed PDF content — \"{0}\".", Collapse(match.Value))));
                    if (++count >= 5 || findings.Count >= _options.MaxFindings) break;
                }
            }
            catch (RegexMatchTimeoutException)
            {
                findings.Add(new PdfFinding("ScanTimeout", "High", string.Format(
                    "The {0} rule exceeded its processing deadline.", rule.Title)));
            }
        }

        private static string Collapse(string value)
        {
            value = Regex.Replace(value, @"\s+", " ").Trim();
            return value.Length <= 90 ? value : value.Substring(0, 90) + "…";
        }

        private sealed class CorpusResult
        {
            public CorpusResult(string corpus, List<PdfFinding> findings)
            { Corpus = corpus; Findings = findings; }
            public string Corpus { get; private set; }
            public List<PdfFinding> Findings { get; private set; }
        }

        private CorpusResult BuildScanCorpus(byte[] data, int length, CancellationToken cancellationToken)
        {
            var findings = new List<PdfFinding>();
            int maxCorpusChars = checked((int)Math.Min(int.MaxValue,
                _options.MaxFileSizeBytes + _options.MaxTotalInflateBytes + 4L * 1024 * 1024));
            var corpus = new BoundedCorpus(maxCorpusChars);
            try
            {
                AppendSegment(corpus, data, 0, length);
                AppendDecodedStreams(data, length, corpus, findings, cancellationToken);
            }
            catch (PdfScanException exception)
            {
                findings.Add(new PdfFinding(exception.Rule, "High", exception.Message));
            }
            return new CorpusResult(corpus.ToString(), findings);
        }

        private static void AppendSegment(BoundedCorpus corpus, byte[] bytes, int offset, int count)
        {
            string normalized = NormalizeNameEscapes(PdfEncoding.GetString(bytes, offset, count));
            corpus.Append(normalized);
            AppendDecodedStrings(normalized, corpus);
        }

        private void AppendDecodedStreams(byte[] data, int length, BoundedCorpus corpus,
            List<PdfFinding> findings, CancellationToken cancellationToken)
        {
            string rawText = PdfEncoding.GetString(data, 0, length);
            int searchFrom = 0, streamCount = 0, totalDecoded = 0;
            while (searchFrom < length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int streamIndex = FindStreamToken(rawText, searchFrom);
                if (streamIndex < 0) break;
                if (++streamCount > _options.MaxStreamCount)
                    throw new PdfScanException("TooManyStreams", string.Format(
                        "The PDF contains more than {0} stream objects.", _options.MaxStreamCount));

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
                    ? NormalizeNameEscapes(rawText.Substring(dictionaryStart, streamIndex - dictionaryStart))
                    : string.Empty;
                List<string> filters = ExtractFilters(header);
                if (filters == null)
                    AddUnscannable(findings, streamCount, "The stream filter is indirect or malformed.");
                else if (filters.Count > 0 && !IsOpaqueImageStream(header, filters))
                {
                    try
                    {
                        byte[] decoded = DecodeFilters(data, dataStart, dataEnd - dataStart, filters,
                            ref totalDecoded, cancellationToken);
                        AppendSegment(corpus, decoded, 0, decoded.Length);
                    }
                    catch (Exception exception)
                    {
                        if (!(exception is InvalidDataException) && !(exception is PdfScanException)) throw;
                        AddUnscannable(findings, streamCount, exception.Message);
                    }
                }
                searchFrom = endIndex + "endstream".Length;
            }
        }

        private void AddUnscannable(List<PdfFinding> findings, int streamNumber, string detail)
        {
            if (_options.RejectUnscannableStreams && findings.Count < _options.MaxFindings)
                findings.Add(new PdfFinding("UnscannableStream", "High", string.Format(
                    "Stream {0} could not be inspected safely: {1}", streamNumber, detail)));
        }

        private static int FindStreamToken(string text, int start)
        {
            while (start < text.Length)
            {
                int index = text.IndexOf("stream", start, StringComparison.Ordinal);
                if (index < 0) return -1;
                int afterIndex = index + 6;
                bool before = index == 0 || IsPdfDelimiterOrWhiteSpace(text[index - 1]);
                bool after = afterIndex < text.Length && (text[afterIndex] == '\r' || text[afterIndex] == '\n');
                if (before && after) return index;
                start = afterIndex;
            }
            return -1;
        }

        private static List<string> ExtractFilters(string header)
        {
            int index = header.LastIndexOf("/Filter", StringComparison.Ordinal);
            if (index < 0) return new List<string>();
            index += "/Filter".Length;
            while (index < header.Length && char.IsWhiteSpace(header[index])) index++;
            if (index >= header.Length) return null;
            string filterText;
            if (header[index] == '[')
            {
                int end = header.IndexOf(']', index + 1);
                if (end < 0 || end - index > 1024) return null;
                filterText = header.Substring(index + 1, end - index - 1);
            }
            else if (header[index] == '/')
            {
                int end = index + 1;
                while (end < header.Length && !IsPdfDelimiterOrWhiteSpace(header[end])) end++;
                filterText = header.Substring(index, end - index);
            }
            else return null;
            return Regex.Matches(filterText, @"/([A-Za-z0-9]+)").Cast<Match>()
                .Select(match => match.Groups[1].Value).ToList();
        }

        private static bool IsOpaqueImageStream(string header, IReadOnlyList<string> filters)
        {
            return filters.Count > 0 && Regex.IsMatch(header, @"/Subtype\s*/Image\b", RegexOptions.CultureInvariant);
        }

        private byte[] DecodeFilters(byte[] encoded, int offset, int count, IReadOnlyList<string> filters,
            ref int totalDecoded, CancellationToken cancellationToken)
        {
            var current = new byte[count];
            Buffer.BlockCopy(encoded, offset, current, 0, count);
            foreach (string filter in filters)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int inputLength = current.Length;
                switch (filter)
                {
                    case "FlateDecode": case "Fl": current = Inflate(current, cancellationToken); break;
                    case "ASCIIHexDecode": case "AHx": current = DecodeAsciiHex(current); break;
                    case "ASCII85Decode": case "A85": current = DecodeAscii85(current); break;
                    case "RunLengthDecode": case "RL": current = DecodeRunLength(current); break;
                    default: throw new InvalidDataException(string.Format("Unsupported stream filter /{0}.", filter));
                }
                if (current.Length > _options.MaxInflateBytes)
                    throw new PdfScanException("InflateLimitExceeded", string.Format(
                        "Decoded stream exceeds {0:N0} bytes.", _options.MaxInflateBytes));
                if (current.Length > Math.Max(1024L, inputLength) * _options.MaxCompressionRatio)
                    throw new PdfScanException("CompressionRatioExceeded", string.Format(
                        "Decoded stream exceeds the {0}:1 expansion limit.", _options.MaxCompressionRatio));
                totalDecoded = checked(totalDecoded + current.Length);
                if (totalDecoded > _options.MaxTotalInflateBytes)
                    throw new PdfScanException("TotalInflateLimitExceeded", string.Format(
                        "Decoded streams exceed the {0:N0}-byte document limit.", _options.MaxTotalInflateBytes));
            }
            return current;
        }

        // PDF FlateDecode is RFC 1950 zlib. net472 only exposes RFC 1951 DeflateStream,
        // so validate/remove the wrapper and verify its Adler-32 checksum explicitly.
        private byte[] Inflate(byte[] input, CancellationToken cancellationToken)
        {
            if (input.Length < 6) throw new InvalidDataException("The FlateDecode stream is too short.");
            int cmf = input[0], flags = input[1];
            if ((cmf & 15) != 8 || (cmf >> 4) > 7 || ((cmf << 8) + flags) % 31 != 0)
                throw new InvalidDataException("The FlateDecode stream has an invalid zlib header.");
            if ((flags & 0x20) != 0)
                throw new InvalidDataException("Preset zlib dictionaries are not supported.");

            byte[] decoded;
            using (var source = new MemoryStream(input, 2, input.Length - 6, false))
            using (var deflate = new DeflateStream(source, CompressionMode.Decompress))
            using (var output = new MemoryStream(Math.Min(_options.MaxInflateBytes, 64 * 1024)))
            {
                var buffer = new byte[8192];
                int read;
                while ((read = deflate.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (output.Length + read > _options.MaxInflateBytes)
                        throw new PdfScanException("InflateLimitExceeded", string.Format(
                            "Decoded stream exceeds {0:N0} bytes.", _options.MaxInflateBytes));
                    output.Write(buffer, 0, read);
                }
                decoded = output.ToArray();
            }
            uint expected = ((uint)input[input.Length - 4] << 24) | ((uint)input[input.Length - 3] << 16) |
                            ((uint)input[input.Length - 2] << 8) | input[input.Length - 1];
            if (Adler32(decoded) != expected)
                throw new InvalidDataException("The FlateDecode stream has an invalid zlib checksum.");
            return decoded;
        }

        private static uint Adler32(byte[] bytes)
        {
            const uint modulus = 65521;
            uint a = 1, b = 0;
            foreach (byte value in bytes) { a = (a + value) % modulus; b = (b + a) % modulus; }
            return (b << 16) | a;
        }

        private static byte[] DecodeAsciiHex(byte[] input)
        {
            using (var output = new MemoryStream(input.Length / 2))
            {
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
        }

        private static byte[] DecodeAscii85(byte[] input)
        {
            using (var output = new MemoryStream(input.Length))
            {
                var group = new byte[5];
                int count = 0;
                foreach (byte value in input)
                {
                    if (char.IsWhiteSpace((char)value) || value == '<' || value == '>') continue;
                    if (value == '~') break;
                    if (value == 'z')
                    {
                        if (count != 0) throw new InvalidDataException("Invalid ASCII85 z shorthand.");
                        output.Write(new byte[] { 0, 0, 0, 0 }, 0, 4);
                        continue;
                    }
                    if (value < 33 || value > 117) throw new InvalidDataException("Invalid ASCII85 stream data.");
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
        }

        private static void WriteAscii85Group(Stream output, byte[] group, int outputCount)
        {
            ulong number = 0;
            for (int index = 0; index < 5; index++) number = number * 85 + (uint)(group[index] - 33);
            if (number > uint.MaxValue) throw new InvalidDataException("ASCII85 group overflow.");
            uint value = (uint)number;
            var bytes = new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value };
            output.Write(bytes, 0, outputCount);
        }

        private static byte[] DecodeRunLength(byte[] input)
        {
            using (var output = new MemoryStream(input.Length))
            {
                int index = 0;
                while (index < input.Length)
                {
                    int length = input[index++];
                    if (length == 128) break;
                    if (length <= 127)
                    {
                        int count = length + 1;
                        if (index + count > input.Length) throw new InvalidDataException("Truncated RunLength stream.");
                        output.Write(input, index, count);
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
        }

        private bool ValidateStructure(byte[] data, int length, string corpus, List<PdfFinding> findings)
        {
            bool valid = true;
            if (_options.RequirePdfStructure)
            {
                int tailLength = Math.Min(length, 4096);
                string tail = PdfEncoding.GetString(data, length - tailLength, tailLength);
                valid &= Require(tail.IndexOf("%%EOF", StringComparison.Ordinal) >= 0, findings,
                    "MissingEofMarker", "The PDF has no EOF marker near the end of the file.");
                valid &= Require(corpus.IndexOf("/Catalog", StringComparison.Ordinal) >= 0, findings,
                    "MissingCatalog", "The PDF catalog was not found.");
                valid &= Require(corpus.IndexOf("/Pages", StringComparison.Ordinal) >= 0, findings,
                    "MissingPageTree", "The PDF page tree was not found.");
                valid &= Require(corpus.IndexOf("startxref", StringComparison.Ordinal) >= 0, findings,
                    "MissingCrossReference", "The PDF has no startxref marker.");
            }
            if (_options.RejectEncryptedPdf && Regex.IsMatch(corpus, @"/Encrypt\b", RegexOptions.CultureInvariant))
            {
                findings.Add(new PdfFinding("EncryptedPdf", "High",
                    "Encrypted PDF strings and streams cannot be inspected without decryption."));
                valid = false;
            }
            return valid && findings.All(finding => finding.Rule != "UnscannableStream" &&
                finding.Rule != "ScanBudgetExceeded" && finding.Rule != "InflateLimitExceeded");
        }

        private static bool Require(bool condition, List<PdfFinding> findings, string rule, string detail)
        {
            if (!condition) findings.Add(new PdfFinding(rule, "High", detail));
            return condition;
        }

        private bool HasPdfMagic(byte[] data, int length)
        {
            int scanLength = Math.Min(length, Math.Max(1, _options.HeaderScanBytes));
            string header = PdfEncoding.GetString(data, 0, scanLength);
            int index = header.IndexOf(PdfMagic, StringComparison.Ordinal);
            return index >= 0 && index + 8 <= header.Length &&
                (header[index + 5] == '1' || header[index + 5] == '2') && header[index + 6] == '.' &&
                header[index + 7] >= '0' && header[index + 7] <= '9';
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
                        int high = HexValue(text[index + 1]), low = HexValue(text[index + 2]);
                        if (high >= 0 && low >= 0)
                        { output.Append((char)((high << 4) | low)); index += 2; continue; }
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
                    int high = -1, cursor = index + 1;
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
                        corpus.Append("\n"); corpus.Append(NormalizeNameEscapes(decoded.ToString())); corpus.Append("\n");
                        index = cursor;
                    }
                }
                else if (text[index] == '(')
                {
                    var decoded = new StringBuilder();
                    int depth = 1, cursor = index + 1;
                    for (; cursor < text.Length && depth > 0; cursor++)
                    {
                        char value = text[cursor];
                        if (value == '\\' && cursor + 1 < text.Length)
                        {
                            char escaped = text[++cursor];
                            if (escaped == '\r')
                            { if (cursor + 1 < text.Length && text[cursor + 1] == '\n') cursor++; continue; }
                            if (escaped == '\n') continue;
                            if (escaped >= '0' && escaped <= '7')
                            {
                                int octal = escaped - '0', digits = 1;
                                while (digits < 3 && cursor + 1 < text.Length && text[cursor + 1] >= '0' && text[cursor + 1] <= '7')
                                { octal = octal * 8 + text[++cursor] - '0'; digits++; }
                                decoded.Append((char)(octal & 0xff)); continue;
                            }
                            switch (escaped)
                            {
                                case 'n': decoded.Append('\n'); break; case 'r': decoded.Append('\r'); break;
                                case 't': decoded.Append('\t'); break; case 'b': decoded.Append('\b'); break;
                                case 'f': decoded.Append('\f'); break; default: decoded.Append(escaped); break;
                            }
                        }
                        else if (value == '(') { depth++; decoded.Append(value); }
                        else if (value == ')') { if (--depth > 0) decoded.Append(value); }
                        else decoded.Append(value);
                    }
                    if (depth == 0)
                    {
                        corpus.Append("\n"); corpus.Append(NormalizeNameEscapes(decoded.ToString())); corpus.Append("\n");
                        index = cursor - 1;
                    }
                }
            }
        }

        private static bool IsPdfDelimiterOrWhiteSpace(char value)
        {
            return char.IsWhiteSpace(value) || value == '(' || value == ')' || value == '<' || value == '>' ||
                value == '[' || value == ']' || value == '{' || value == '}' || value == '/' || value == '%';
        }

        private static int HexValue(char value)
        {
            if (value >= '0' && value <= '9') return value - '0';
            if (value >= 'a' && value <= 'f') return value - 'a' + 10;
            if (value >= 'A' && value <= 'F') return value - 'A' + 10;
            return -1;
        }

        private sealed class BoundedCorpus
        {
            private readonly int _maxChars;
            private readonly StringBuilder _builder;
            public BoundedCorpus(int maxChars)
            { _maxChars = maxChars; _builder = new StringBuilder(Math.Min(maxChars, 1024 * 1024)); }
            public void Append(string value)
            {
                if ((long)_builder.Length + value.Length > _maxChars)
                    throw new PdfScanException("ScanBudgetExceeded", string.Format(
                        "The normalized PDF content exceeds the {0:N0}-character scan budget.", _maxChars));
                _builder.Append(value);
            }
            public override string ToString() { return _builder.ToString(); }
        }

        private sealed class PdfScanException : Exception
        {
            public PdfScanException(string rule, string message) : base(message) { Rule = rule; }
            public string Rule { get; private set; }
        }
    }
}
