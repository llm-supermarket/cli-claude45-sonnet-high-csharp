using Org.BouncyCastle.Crypto.Generators;
using RcloneEncrypt.Encoders;
using System.Security.Cryptography;
using System.Text;

namespace RcloneEncrypt.Crypto;

internal sealed class RcloneCipher
{
    // rclone's built-in salt (used when no salt/password2 is provided)
    private static readonly byte[] DefaultSalt =
    [
        0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08,
        0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1
    ];

    private static readonly byte[] FileMagic = "RCLONE\x00\x00"u8.ToArray();
    private const int FileNonceSize = 24;
    private const int FileHeaderSize = 8 + FileNonceSize; // 32
    private const int BlockDataSize = 64 * 1024; // 65536
    private const int BlockOverhead = SecretBox.Overhead; // 16 (Poly1305 tag)
    private const int BlockTotalSize = BlockDataSize + BlockOverhead;
    private const int NameBlockSize = 16; // AES block size for EME

    private readonly byte[] _dataKey = new byte[32];
    private readonly byte[] _nameKey = new byte[32];
    private readonly byte[] _nameTweak = new byte[NameBlockSize];

    private RcloneCipher() { }

    internal static RcloneCipher Create(string password, string? salt = null)
    {
        byte[] saltBytes = salt is null ? DefaultSalt : Encoding.UTF8.GetBytes(salt);
        int keyLen = 32 + 32 + NameBlockSize; // 80 bytes
        byte[] key = SCrypt.Generate(Encoding.UTF8.GetBytes(password), saltBytes, 16384, 8, 1, keyLen);

        var cipher = new RcloneCipher();
        Array.Copy(key, 0, cipher._dataKey, 0, 32);
        Array.Copy(key, 32, cipher._nameKey, 0, 32);
        Array.Copy(key, 64, cipher._nameTweak, 0, NameBlockSize);
        return cipher;
    }

    // Encrypt filename segment using EME-AES + base32hex/base64
    internal string EncryptFileName(string name, FilenameEncoding encoding)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(name);
        byte[] padded = Pkcs7Pad(plainBytes, NameBlockSize);
        byte[] encrypted = EmeCipher.Encrypt(_nameKey, _nameTweak, padded);
        return FilenameEncoder.Encode(encrypted, encoding);
    }

    // Decrypt filename segment
    internal string DecryptFileName(string encodedName, FilenameEncoding encoding)
    {
        byte[] raw = FilenameEncoder.Decode(encodedName, encoding);
        if (raw.Length == 0) throw new CryptographicException("Empty decoded filename");
        if (raw.Length % NameBlockSize != 0) throw new CryptographicException("Decoded filename is not a multiple of block size");
        byte[] decrypted = EmeCipher.Decrypt(_nameKey, _nameTweak, raw);
        byte[] unpadded = Pkcs7Unpad(decrypted, NameBlockSize);
        return Encoding.UTF8.GetString(unpadded);
    }

    // Encrypt file content from inputStream → outputStream
    internal async Task EncryptFileAsync(Stream inputStream, Stream outputStream, CancellationToken ct = default)
    {
        // Write header: magic + random nonce
        byte[] nonce = new byte[FileNonceSize];
        RandomNumberGenerator.Fill(nonce);
        await outputStream.WriteAsync(FileMagic, ct);
        await outputStream.WriteAsync(nonce, ct);

        byte[] nonceCopy = (byte[])nonce.Clone();
        byte[] buffer = new byte[BlockDataSize];
        int read;

        while ((read = await inputStream.ReadAsync(buffer.AsMemory(0, BlockDataSize), ct)) > 0)
        {
            byte[] block = buffer[..read];
            byte[] encrypted = SecretBox.Seal(block, nonceCopy, _dataKey);
            await outputStream.WriteAsync(encrypted, ct);
            IncrementNonce(nonceCopy);
        }
    }

    // Decrypt file content from inputStream → outputStream
    internal async Task DecryptFileAsync(Stream inputStream, Stream outputStream, CancellationToken ct = default)
    {
        // Read and verify header
        byte[] header = new byte[FileHeaderSize];
        await ReadExactAsync(inputStream, header, ct);

        byte[] magic = header[..8];
        if (!magic.SequenceEqual(FileMagic))
            throw new CryptographicException("Not an rclone encrypted file (bad magic)");

        byte[] nonce = header[8..];
        byte[] nonceCopy = (byte[])nonce.Clone();
        byte[] buffer = new byte[BlockTotalSize];
        int read;

        while ((read = await inputStream.ReadAsync(buffer.AsMemory(0, BlockTotalSize), ct)) > 0)
        {
            byte[] encBlock = buffer[..read];
            byte[] plain = SecretBox.Open(encBlock, nonceCopy, _dataKey);
            await outputStream.WriteAsync(plain, ct);
            IncrementNonce(nonceCopy);
        }
    }

    // Nonce is a little-endian counter incremented by 1
    private static void IncrementNonce(byte[] nonce)
    {
        for (int i = 0; i < nonce.Length; i++)
        {
            if (++nonce[i] != 0) break;
        }
    }

    private static byte[] Pkcs7Pad(byte[] data, int blockSize)
    {
        int padLen = blockSize - (data.Length % blockSize);
        byte[] padded = new byte[data.Length + padLen];
        Array.Copy(data, padded, data.Length);
        for (int i = data.Length; i < padded.Length; i++)
            padded[i] = (byte)padLen;
        return padded;
    }

    private static byte[] Pkcs7Unpad(byte[] data, int blockSize)
    {
        if (data.Length == 0 || data.Length % blockSize != 0)
            throw new CryptographicException("Invalid PKCS7 padding length");
        int padLen = data[^1];
        if (padLen == 0 || padLen > blockSize)
            throw new CryptographicException("Invalid PKCS7 padding value");
        for (int i = data.Length - padLen; i < data.Length; i++)
            if (data[i] != padLen)
                throw new CryptographicException("Invalid PKCS7 padding bytes");
        return data[..^padLen];
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(total), ct);
            if (read == 0) throw new EndOfStreamException("Unexpected end of stream reading file header");
            total += read;
        }
    }
}
