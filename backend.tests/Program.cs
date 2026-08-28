using System.IO.Compression;
using System.Text;
using PdfSecurityApi.Security;

var scanner = new PdfSecurity();
var failures = new List<string>();
var workspace = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));

Check("clean PDF is accepted", () =>
{
    var result = scanner.Validate(File.ReadAllBytes(Path.Combine(workspace, "benign.pdf")), "benign.pdf");
    return result.IsAllowed && result.IsValidPdf;
});

Check("header-only fake is rejected", () =>
    !scanner.Validate(Encoding.Latin1.GetBytes("%PDF-1.7 this is not a PDF"), "fake.pdf").IsAllowed);

Check("plain JavaScript action is rejected", () =>
    IsRejectedWith(BuildPdf("<< /S /JavaScript /JS (app.alert(1)) >>", "/OpenAction 4 0 R"),
        "JavaScript action"));

Check("escaped names and hex JavaScript are rejected", () =>
    IsRejectedWith(BuildPdf("<< /S /J#61vaScript /J#53 <6170702e616c657274283129> >>",
        "/Open#41ction 4 0 R"), "JavaScript action"));

Check("encrypted PDF is rejected", () =>
    IsRejectedWith(BuildPdf("<< /Filter /Standard /V 4 /Length 128 >>", string.Empty, "/Encrypt 4 0 R"),
        "EncryptedPdf"));

Check("unsupported non-image stream filter fails closed", () =>
    IsRejectedWith(BuildPdf("<< /Length 3 /Filter /LZWDecode >>\nstream\nabc\nendstream"),
        "UnscannableStream"));

Check("ASCIIHex stream is decoded before scanning", () =>
{
    const string dangerous = "/S /JavaScript /JS (app.alert(1))";
    string hex = Convert.ToHexString(Encoding.Latin1.GetBytes(dangerous));
    string stream = $"<< /Length {hex.Length} /Filter /ASCIIHexDecode >>\nstream\n{hex}>\nendstream";
    return IsRejectedWith(BuildPdf(stream), "JavaScript action");
});

Check("oversized decompression fails closed", () =>
{
    byte[] expanded = new byte[2_200_000];
    Encoding.Latin1.GetBytes("/S /JavaScript /JS (app.alert(1))").CopyTo(expanded, 0);
    byte[] compressed;
    using (var target = new MemoryStream())
    {
        using (var zlib = new ZLibStream(target, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            zlib.Write(expanded);
        }
        compressed = target.ToArray();
    }
    string stream = $"<< /Length {compressed.Length} /Filter /FlateDecode >>\nstream\n" +
                    Encoding.Latin1.GetString(compressed) + "\nendstream";
    return IsRejectedWith(BuildPdf(stream), "UnscannableStream");
});

if (failures.Count > 0)
{
    Console.Error.WriteLine($"FAILED: {failures.Count} security regression test(s)");
    foreach (string failure in failures) Console.Error.WriteLine($"  - {failure}");
    return 1;
}

Console.WriteLine("PASS: all PDF security regression tests succeeded.");
return 0;

void Check(string name, Func<bool> assertion)
{
    try
    {
        if (assertion())
        {
            Console.WriteLine($"PASS: {name}");
        }
        else
        {
            failures.Add(name);
            Console.Error.WriteLine($"FAIL: {name}");
        }
    }
    catch (Exception exception)
    {
        failures.Add($"{name} ({exception.GetType().Name}: {exception.Message})");
        Console.Error.WriteLine($"FAIL: {name} ({exception.Message})");
    }
}

bool IsRejectedWith(byte[] pdf, string rule)
{
    var result = scanner.Validate(pdf, "test.pdf");
    return !result.IsAllowed && result.Findings.Any(finding => finding.Rule == rule);
}

static byte[] BuildPdf(string fourthObject, string catalogExtra = "", string trailerExtra = "")
{
    string[] objects =
    [
        $"<< /Type /Catalog /Pages 2 0 R {catalogExtra} >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
        fourthObject
    ];

    var document = new StringBuilder("%PDF-1.7\n");
    var offsets = new List<int> { 0 };
    for (int index = 0; index < objects.Length; index++)
    {
        offsets.Add(document.Length);
        document.Append(index + 1).Append(" 0 obj\n")
            .Append(objects[index]).Append("\nendobj\n");
    }

    int xrefOffset = document.Length;
    document.Append("xref\n0 ").Append(objects.Length + 1)
        .Append("\n0000000000 65535 f \n");
    foreach (int offset in offsets.Skip(1))
    {
        document.Append(offset.ToString("D10")).Append(" 00000 n \n");
    }
    document.Append("trailer\n<< /Size ").Append(objects.Length + 1)
        .Append(" /Root 1 0 R ").Append(trailerExtra).Append(" >>\nstartxref\n")
        .Append(xrefOffset).Append("\n%%EOF\n");
    return Encoding.Latin1.GetBytes(document.ToString());
}
