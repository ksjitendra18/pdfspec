namespace PdfSecurityApi.Security
{
    /// <summary>Configuration shared by the modern API and .NET Framework 4.7.2 callers.</summary>
    public sealed class PdfSecurityOptions
    {
        public long MaxFileSizeBytes { get; set; } = 10 * 1024 * 1024;
        public int MaxInflateBytes { get; set; } = 2 * 1024 * 1024;
        public int MaxTotalInflateBytes { get; set; } = 8 * 1024 * 1024;
        public int MaxStreamCount { get; set; } = 256;
        public int MaxCompressionRatio { get; set; } = 200;
        public int MaxFindings { get; set; } = 100;
        public bool BlockJavaScript { get; set; } = true;
        public bool BlockExternalLinks { get; set; } = true;
        public bool BlockEmbeddedFiles { get; set; } = true;
        public bool BlockCommandExecution { get; set; } = true;
        public bool BlockAnnotationInjection { get; set; } = true;
        public bool RequirePdfHeader { get; set; } = true;
        public bool RequirePdfStructure { get; set; } = true;
        public bool RejectEncryptedPdf { get; set; } = true;
        public bool RejectUnscannableStreams { get; set; } = true;
        public int HeaderScanBytes { get; set; } = 1024;
    }
}
