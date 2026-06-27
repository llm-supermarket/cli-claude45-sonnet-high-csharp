using FluentAssertions;
using RcloneEncrypt.Crypto;
using RcloneEncrypt.Encoders;
using System.IO;
using System.Text;
using Xunit;

namespace RcloneEncrypt.Tests;

public class CryptoTests
{
    private const string TestPassword = "Testpassword1";
    private const string TestFilename = "TEST_FILE.txt";
    private const string TestFilenameBase64 = "TEST_FILE BASE64.txt";

    // Known encrypted filenames from the repository
    private const string Base32EncryptedName = "kr9tu4e1da4u3nifdd99g9tf5o";
    private const string Base64EncryptedName = "Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY";

    [Fact]
    public void DecryptBase32Filename_WithKnownPassword_ReturnsTestFilename()
    {
        var cipher = RcloneCipher.Create(TestPassword);
        string decrypted = cipher.DecryptFileName(Base32EncryptedName, FilenameEncoding.Base32);
        decrypted.Should().Be(TestFilename);
    }

    [Fact]
    public void DecryptBase64Filename_WithKnownPassword_ReturnsTestFilenameBase64()
    {
        var cipher = RcloneCipher.Create(TestPassword);
        string decrypted = cipher.DecryptFileName(Base64EncryptedName, FilenameEncoding.Base64);
        decrypted.Should().Be(TestFilenameBase64);
    }

    [Fact]
    public void EncryptThenDecryptFilename_Base32_RoundTrips()
    {
        var cipher = RcloneCipher.Create(TestPassword);
        string encrypted = cipher.EncryptFileName(TestFilename, FilenameEncoding.Base32);
        string decrypted = cipher.DecryptFileName(encrypted, FilenameEncoding.Base32);
        decrypted.Should().Be(TestFilename);
    }

    [Fact]
    public void EncryptThenDecryptFilename_Base64_RoundTrips()
    {
        var cipher = RcloneCipher.Create(TestPassword);
        string encrypted = cipher.EncryptFileName(TestFilename, FilenameEncoding.Base64);
        string decrypted = cipher.DecryptFileName(encrypted, FilenameEncoding.Base64);
        decrypted.Should().Be(TestFilename);
    }

    [Fact]
    public void EncryptFilename_IsDeteterministic_SamePasswordSameName()
    {
        var cipher1 = RcloneCipher.Create(TestPassword);
        var cipher2 = RcloneCipher.Create(TestPassword);
        cipher1.EncryptFileName(TestFilename, FilenameEncoding.Base32)
            .Should().Be(cipher2.EncryptFileName(TestFilename, FilenameEncoding.Base32));
    }

    [Fact]
    public async Task EncryptThenDecryptFile_NoSalt_RoundTrips()
    {
        const string content = "abandon ability able about above absent absorb abstract";
        var cipher = RcloneCipher.Create(TestPassword);

        byte[] plainBytes = Encoding.UTF8.GetBytes(content);
        using var plainStream = new MemoryStream(plainBytes);
        using var encStream = new MemoryStream();
        await cipher.EncryptFileAsync(plainStream, encStream);

        encStream.Position = 0;
        using var decStream = new MemoryStream();
        await cipher.DecryptFileAsync(encStream, decStream);

        string result = Encoding.UTF8.GetString(decStream.ToArray());
        result.Should().Be(content);
    }

    [Fact]
    public async Task EncryptThenDecryptFile_WithSalt_RoundTrips()
    {
        const string content = "abandon ability able about above absent absorb abstract";
        const string salt = "mysalt123";
        var cipher = RcloneCipher.Create(TestPassword, salt);

        byte[] plainBytes = Encoding.UTF8.GetBytes(content);
        using var plainStream = new MemoryStream(plainBytes);
        using var encStream = new MemoryStream();
        await cipher.EncryptFileAsync(plainStream, encStream);

        encStream.Position = 0;
        using var decStream = new MemoryStream();
        await cipher.DecryptFileAsync(encStream, decStream);

        string result = Encoding.UTF8.GetString(decStream.ToArray());
        result.Should().Be(content);
    }

    [Fact]
    public async Task DecryptFile_WrongPassword_ThrowsCryptographicException()
    {
        var goodCipher = RcloneCipher.Create(TestPassword);
        var badCipher = RcloneCipher.Create("WrongPassword");

        byte[] plainBytes = Encoding.UTF8.GetBytes("test content");
        using var plainStream = new MemoryStream(plainBytes);
        using var encStream = new MemoryStream();
        await goodCipher.EncryptFileAsync(plainStream, encStream);

        encStream.Position = 0;
        using var decStream = new MemoryStream();
        Func<Task> act = () => badCipher.DecryptFileAsync(encStream, decStream);
        await act.Should().ThrowAsync<System.Security.Cryptography.CryptographicException>();
    }

    [Fact]
    public async Task EncryptThenDecryptLargeFile_MultipleBlocks_RoundTrips()
    {
        // Generate data larger than one 64K block
        byte[] content = new byte[200_000];
        Random.Shared.NextBytes(content);
        var cipher = RcloneCipher.Create(TestPassword);

        using var plainStream = new MemoryStream(content);
        using var encStream = new MemoryStream();
        await cipher.EncryptFileAsync(plainStream, encStream);

        encStream.Position = 0;
        using var decStream = new MemoryStream();
        await cipher.DecryptFileAsync(encStream, decStream);

        decStream.ToArray().Should().Equal(content);
    }

    [Fact]
    public void EncryptFilename_DifferentSalt_ProducesDifferentResult()
    {
        var cipher1 = RcloneCipher.Create(TestPassword);
        var cipher2 = RcloneCipher.Create(TestPassword, "custom-salt");
        cipher1.EncryptFileName(TestFilename, FilenameEncoding.Base32)
            .Should().NotBe(cipher2.EncryptFileName(TestFilename, FilenameEncoding.Base32));
    }

    [Fact]
    public void EncryptFilename_Base64Encoding_ProducesBase64Output()
    {
        var cipher = RcloneCipher.Create(TestPassword);
        string encrypted = cipher.EncryptFileName(TestFilename, FilenameEncoding.Base64);
        // base64 url-safe chars are A-Z, a-z, 0-9, -, _  (no = padding)
        encrypted.Should().MatchRegex("^[A-Za-z0-9_-]+$");
    }

    [Fact]
    public void EncryptFilename_Base32Encoding_ProducesLowercaseHexBase32Output()
    {
        var cipher = RcloneCipher.Create(TestPassword);
        string encrypted = cipher.EncryptFileName(TestFilename, FilenameEncoding.Base32);
        // base32hex lowercase: 0-9, a-v
        encrypted.Should().MatchRegex("^[0-9a-v]+$");
    }
}
