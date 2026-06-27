using System.CommandLine;
using System.Reflection;
using RcloneEncrypt.Crypto;
using RcloneEncrypt.Encoders;

var version = typeof(Program).Assembly
    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
    ?? "1.0.0";

var rootCommand = new RootCommand("rclone-encrypt-claude45-sonnet: encrypt/decrypt files using rclone's crypt format");

// shared options
var inputOption = new Option<FileInfo?>(
    aliases: ["--input-file", "-i"],
    description: "Input file path") { IsRequired = true };

var outputOption = new Option<FileInfo?>(
    aliases: ["--output-file", "-o"],
    description: "Output file path (optional; derived from decrypted/encrypted filename when omitted)");

var passwordOption = new Option<string?>(
    aliases: ["--password"],
    description: "Password (WARNING: visible in shell history and process list; prefer the RCLONE_ENCRYPT_PASSWORD environment variable or interactive prompt)");

var saltOption = new Option<string?>(
    aliases: ["--salt"],
    description: "Optional salt / password2 (uses rclone's built-in salt when omitted)");

var encodingOption = new Option<string>(
    aliases: ["--filename-encoding"],
    description: "Filename encoding: base32 (default, rclone standard) or base64",
    getDefaultValue: () => "base32");

// --version flag
var versionOption = new Option<bool>("--version", "Print version and exit");
rootCommand.AddOption(versionOption);
rootCommand.SetHandler(showVersion =>
{
    if (showVersion) Console.WriteLine($"cli-claude45-sonnet-csharp {version}");
}, versionOption);

// encrypt command
var encryptCommand = new Command("encrypt", "Encrypt a file using rclone's crypt format");
encryptCommand.AddOption(inputOption);
encryptCommand.AddOption(outputOption);
encryptCommand.AddOption(passwordOption);
encryptCommand.AddOption(saltOption);
encryptCommand.AddOption(encodingOption);
encryptCommand.SetHandler(async (input, output, password, salt, encodingStr) =>
{
    var encoding = ParseEncoding(encodingStr);
    string pwd = ResolvePassword(password);
    var cipher = RcloneCipher.Create(pwd, salt);

    string inputPath = input!.FullName;
    string encryptedName = cipher.EncryptFileName(input.Name, encoding);
    string outputPath = output?.FullName ?? Path.Combine(input.DirectoryName ?? ".", encryptedName);

    Console.Error.WriteLine($"Encrypting {input.Name} → {Path.GetFileName(outputPath)}");
    await using var inputStream = File.OpenRead(inputPath);
    await using var outputStream = File.Create(outputPath);
    await cipher.EncryptFileAsync(inputStream, outputStream);
    Console.Error.WriteLine("Done.");
}, inputOption, outputOption, passwordOption, saltOption, encodingOption);

// decrypt command
var decryptCommand = new Command("decrypt", "Decrypt a file encrypted with rclone's crypt format");
decryptCommand.AddOption(inputOption);
decryptCommand.AddOption(outputOption);
decryptCommand.AddOption(passwordOption);
decryptCommand.AddOption(saltOption);
decryptCommand.AddOption(encodingOption);
decryptCommand.SetHandler(async (input, output, password, salt, encodingStr) =>
{
    var encoding = ParseEncoding(encodingStr);
    string pwd = ResolvePassword(password);
    var cipher = RcloneCipher.Create(pwd, salt);

    string inputPath = input!.FullName;

    string decryptedName;
    try
    {
        decryptedName = cipher.DecryptFileName(input.Name, encoding);
    }
    catch
    {
        // If name decryption fails, use original name + .decrypted
        decryptedName = input.Name + ".decrypted";
        Console.Error.WriteLine($"Warning: could not decrypt filename, using '{decryptedName}'");
    }

    string outputPath = output?.FullName ?? Path.Combine(input.DirectoryName ?? ".", decryptedName);

    Console.Error.WriteLine($"Decrypting {input.Name} → {Path.GetFileName(outputPath)}");
    await using var inputStream = File.OpenRead(inputPath);
    await using var outputStream = File.Create(outputPath);
    await cipher.DecryptFileAsync(inputStream, outputStream);
    Console.Error.WriteLine("Done.");
}, inputOption, outputOption, passwordOption, saltOption, encodingOption);

rootCommand.AddCommand(encryptCommand);
rootCommand.AddCommand(decryptCommand);

return await rootCommand.InvokeAsync(args);

static FilenameEncoding ParseEncoding(string s) =>
    s.ToLowerInvariant() switch
    {
        "base32" => FilenameEncoding.Base32,
        "base64" => FilenameEncoding.Base64,
        _ => throw new ArgumentException($"Unknown encoding '{s}'. Use base32 or base64.")
    };

static string ResolvePassword(string? flagPassword)
{
    if (flagPassword is not null)
    {
        Console.Error.WriteLine(
            "SECURITY WARNING: --password is visible in shell history and process list.\n" +
            "Prefer the RCLONE_ENCRYPT_PASSWORD environment variable, or omit for interactive prompt.\n" +
            "After use, clear history: `history -d $(history 1)` (bash) or `Clear-History` (PowerShell).");
        return flagPassword;
    }

    string? envPwd = Environment.GetEnvironmentVariable("RCLONE_ENCRYPT_PASSWORD");
    if (envPwd is not null)
        return envPwd;

    return PromptPassword("Password: ");
}

static string PromptPassword(string prompt)
{
    Console.Error.Write(prompt);
    var password = new System.Text.StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace)
        {
            if (password.Length > 0) password.Remove(password.Length - 1, 1);
        }
        else if (key.KeyChar != '\0')
        {
            password.Append(key.KeyChar);
        }
    }
    Console.Error.WriteLine();
    return password.ToString();
}

internal sealed partial class Program;
