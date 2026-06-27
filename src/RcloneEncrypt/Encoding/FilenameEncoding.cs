namespace RcloneEncrypt.Encoders;

// Filename encoding schemes matching rclone's crypt backend
internal enum FilenameEncoding { Base32, Base64 }

internal static class FilenameEncoder
{
    // rclone's base32 = base32hex (0-9A-V) lowercased, no padding
    private const string Base32HexAlphabet = "0123456789abcdefghijklmnopqrstuv";

    internal static string Encode(byte[] data, FilenameEncoding encoding) =>
        encoding switch
        {
            FilenameEncoding.Base32 => EncodeBase32Hex(data),
            FilenameEncoding.Base64 => EncodeBase64Url(data),
            _ => throw new ArgumentOutOfRangeException(nameof(encoding))
        };

    internal static byte[] Decode(string s, FilenameEncoding encoding) =>
        encoding switch
        {
            FilenameEncoding.Base32 => DecodeBase32Hex(s),
            FilenameEncoding.Base64 => DecodeBase64Url(s),
            _ => throw new ArgumentOutOfRangeException(nameof(encoding))
        };

    private static string EncodeBase32Hex(byte[] data)
    {
        // base32hex lowercase, no padding
        if (data.Length == 0) return string.Empty;
        var sb = new System.Text.StringBuilder();
        int buffer = 0, bitsLeft = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                sb.Append(Base32HexAlphabet[(buffer >> bitsLeft) & 0x1F]);
            }
        }
        if (bitsLeft > 0)
            sb.Append(Base32HexAlphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        return sb.ToString();
    }

    private static byte[] DecodeBase32Hex(string s)
    {
        if (string.IsNullOrEmpty(s)) return [];
        s = s.ToLowerInvariant();
        // add padding to make length a multiple of 8
        int padLen = (8 - s.Length % 8) % 8;
        string padded = s + new string('=', padLen);
        // use .NET's base32 by mapping: rclone uses HexEncoding alphabet (0-9A-V)
        // convert from hex32 to standard base32 chars and decode
        // Alternatively, decode manually:
        var result = new System.Collections.Generic.List<byte>();
        int buffer = 0, bitsLeft = 0;
        foreach (char c in s)
        {
            int val = Base32HexAlphabet.IndexOf(c);
            if (val < 0) throw new FormatException($"Invalid base32hex character: {c}");
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                result.Add((byte)((buffer >> bitsLeft) & 0xFF));
            }
        }
        return [.. result];
    }

    private static string EncodeBase64Url(byte[] data) =>
        Convert.ToBase64String(data)
            .Replace('+', '-').Replace('/', '_')
            .TrimEnd('=');

    private static byte[] DecodeBase64Url(string s)
    {
        string b64 = s.Replace('-', '+').Replace('_', '/');
        int pad = (4 - b64.Length % 4) % 4;
        b64 += new string('=', pad);
        return Convert.FromBase64String(b64);
    }
}
