using System.Collections.Generic;
using System.Linq;

// Nullable reference annotations do not exist in the C# 7.3 build used for net472.
#pragma warning disable CS8618

namespace PdfSecurityApi.Security
{
    public sealed class PdfFinding
    {
        public PdfFinding(string rule, string severity, string detail)
        {
            Rule = rule;
            Severity = severity;
            Detail = detail;
        }

        public string Rule { get; private set; }
        public string Severity { get; private set; }
        public string Detail { get; private set; }
    }

    public sealed class PdfValidationResult
    {
        public bool IsValidPdf { get; set; }
        public bool IsAllowed { get; set; }
        public long SizeBytes { get; set; }
        public string FileName { get; set; }
        public string Summary { get; set; } = string.Empty;
        public IReadOnlyList<string> Reasons { get; set; } = new string[0];
        public IReadOnlyList<PdfFinding> Findings { get; set; } = new PdfFinding[0];

        public static PdfValidationResult Ok(string fileName, long size, string summary)
        {
            return new PdfValidationResult
            {
                IsValidPdf = true, IsAllowed = true, SizeBytes = size, FileName = fileName,
                Summary = summary, Reasons = new string[0], Findings = new PdfFinding[0]
            };
        }

        public static PdfValidationResult Rejected(bool validPdf, string fileName, long size,
            string summary, IReadOnlyList<PdfFinding> findings)
        {
            List<string> reasons = findings
                .Select(finding => string.Format("{0}: {1}", finding.Rule, finding.Detail))
                .Distinct().ToList();
            if (reasons.Count == 0) reasons.Add(summary);
            return new PdfValidationResult
            {
                IsValidPdf = validPdf, IsAllowed = false, SizeBytes = size, FileName = fileName,
                Summary = summary, Reasons = reasons, Findings = findings
            };
        }
    }
}
