using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using PdfSecurityApi.Security;

internal static class Program
{
    private static readonly Encoding PdfEncoding = Encoding.GetEncoding(28591);
    private static readonly PdfSecurity Scanner = new PdfSecurity();
    private static readonly List<string> Failures = new List<string>();

    private static int Main()
    {
        Check("clean PDF is accepted", delegate
        {
            PdfValidationResult result = Scanner.Validate(BuildPdf("<< >>"), "clean.pdf");
            return result.IsAllowed && result.IsValidPdf;
        });
        Check("header-only fake is rejected", delegate
        {
            return !Scanner.Validate(PdfEncoding.GetBytes("%PDF-1.7 fake"), "fake.pdf").IsAllowed;
        });
        Check("plain JavaScript action is rejected", delegate
        {
            return IsRejectedWith(BuildPdf("<< /S /JavaScript /JS (app.alert(1)) >>", "/OpenAction 4 0 R"),
                "JavaScript action");
        });
        Check("escaped names and hex JavaScript are rejected", delegate
        {
            return IsRejectedWith(BuildPdf("<< /S /J#61vaScript /J#53 <6170702e616c657274283129> >>",
                "/Open#41ction 4 0 R"), "JavaScript action");
        });
        Check("encrypted PDF is rejected", delegate
        {
            return IsRejectedWith(BuildPdf("<< /Filter /Standard /V 4 /Length 128 >>", "", "/Encrypt 4 0 R"),
                "EncryptedPdf");
        });
        Check("unsupported stream filter fails closed", delegate
        {
            return IsRejectedWith(BuildPdf("<< /Length 3 /Filter /LZWDecode >>\nstream\nabc\nendstream"),
                "UnscannableStream");
        });
        Check("ASCIIHex stream is decoded", delegate
        {
            string dangerous = "/S /JavaScript /JS (app.alert(1))";
            string hex = ToHex(PdfEncoding.GetBytes(dangerous));
            return IsRejectedWith(BuildPdf(string.Format(
                "<< /Length {0} /Filter /ASCIIHexDecode >>\nstream\n{1}>\nendstream", hex.Length, hex)),
                "JavaScript action");
        });
        Check("FlateDecode zlib stream is decoded", delegate
        {
            byte[] compressed = ZlibCompress(PdfEncoding.GetBytes("/S /JavaScript /JS (app.alert(1))"));
            string stream = string.Format("<< /Length {0} /Filter /FlateDecode >>\nstream\n{1}\nendstream",
                compressed.Length, PdfEncoding.GetString(compressed));
            return IsRejectedWith(BuildPdf(stream), "JavaScript action");
        });

        if (Failures.Count == 0)
        {
            Console.WriteLine("PASS: all .NET Framework 4.7.2 security tests succeeded.");
            return 0;
        }
        Console.Error.WriteLine("FAILED: " + Failures.Count + " test(s)");
        foreach (string failure in Failures) Console.Error.WriteLine("  - " + failure);
        return 1;
    }

    private static void Check(string name, Func<bool> assertion)
    {
        try
        {
            if (assertion()) Console.WriteLine("PASS: " + name);
            else { Failures.Add(name); Console.Error.WriteLine("FAIL: " + name); }
        }
        catch (Exception exception)
        {
            Failures.Add(name + " (" + exception.GetType().Name + ": " + exception.Message + ")");
            Console.Error.WriteLine("FAIL: " + name + " (" + exception.Message + ")");
        }
    }

    private static bool IsRejectedWith(byte[] pdf, string rule)
    {
        PdfValidationResult result = Scanner.Validate(pdf, "test.pdf");
        return !result.IsAllowed && result.Findings.Any(finding => finding.Rule == rule);
    }

    private static byte[] BuildPdf(string fourthObject, string catalogExtra = "", string trailerExtra = "")
    {
        string[] objects =
        {
            string.Format("<< /Type /Catalog /Pages 2 0 R {0} >>", catalogExtra),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            fourthObject
        };
        var document = new StringBuilder("%PDF-1.7\n");
        var offsets = new List<int> { 0 };
        for (int index = 0; index < objects.Length; index++)
        {
            offsets.Add(document.Length);
            document.Append(index + 1).Append(" 0 obj\n").Append(objects[index]).Append("\nendobj\n");
        }
        int xrefOffset = document.Length;
        document.Append("xref\n0 ").Append(objects.Length + 1).Append("\n0000000000 65535 f \n");
        foreach (int offset in offsets.Skip(1))
            document.Append(offset.ToString("D10")).Append(" 00000 n \n");
        document.Append("trailer\n<< /Size ").Append(objects.Length + 1).Append(" /Root 1 0 R ")
            .Append(trailerExtra).Append(" >>\nstartxref\n").Append(xrefOffset).Append("\n%%EOF\n");
        return PdfEncoding.GetBytes(document.ToString());
    }

    private static byte[] ZlibCompress(byte[] input)
    {
        byte[] deflated;
        using (var target = new MemoryStream())
        {
            using (var stream = new DeflateStream(target, CompressionLevel.Optimal, true))
                stream.Write(input, 0, input.Length);
            deflated = target.ToArray();
        }
        uint adler = Adler32(input);
        using (var zlib = new MemoryStream())
        {
            zlib.WriteByte(0x78); zlib.WriteByte(0x9c);
            zlib.Write(deflated, 0, deflated.Length);
            zlib.WriteByte((byte)(adler >> 24)); zlib.WriteByte((byte)(adler >> 16));
            zlib.WriteByte((byte)(adler >> 8)); zlib.WriteByte((byte)adler);
            return zlib.ToArray();
        }
    }

    private static uint Adler32(byte[] bytes)
    {
        const uint modulus = 65521;
        uint a = 1, b = 0;
        foreach (byte value in bytes) { a = (a + value) % modulus; b = (b + a) % modulus; }
        return (b << 16) | a;
    }

    private static string ToHex(byte[] bytes)
    {
        var result = new StringBuilder(bytes.Length * 2);
        foreach (byte value in bytes) result.Append(value.ToString("x2"));
        return result.ToString();
    }
}
