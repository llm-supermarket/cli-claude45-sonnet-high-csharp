using System.Security.Cryptography;

namespace RcloneEncrypt.Crypto;

// EME (Encrypt-Mix-Encrypt) wide-block cipher mode
// Port of https://github.com/rfjakob/eme (used by rclone)
internal static class EmeCipher
{
    private const int BlockSize = 16;

    internal static byte[] Encrypt(byte[] aesKey, byte[] tweak, byte[] plaintext) =>
        Transform(aesKey, tweak, plaintext, forEncrypt: true);

    internal static byte[] Decrypt(byte[] aesKey, byte[] tweak, byte[] ciphertext) =>
        Transform(aesKey, tweak, ciphertext, forEncrypt: false);

    private static byte[] Transform(byte[] aesKey, byte[] tweak, byte[] data, bool forEncrypt)
    {
        if (data.Length % BlockSize != 0 || data.Length == 0)
            throw new ArgumentException("Data must be a non-empty multiple of 16 bytes");
        if (tweak.Length != BlockSize)
            throw new ArgumentException("Tweak must be 16 bytes");

        int m = data.Length / BlockSize;
        byte[] C = new byte[data.Length];

        using var aes = Aes.Create();
        aes.Key = aesKey;

        // tabulateL: LTable[j] = 2^(j+1) * AES_ENCRYPT(0^16)
        // L always uses the FORWARD AES (encrypt), regardless of direction — see rfjakob/eme
        byte[] zeroBlock = new byte[BlockSize];
        byte[] L = aes.EncryptEcb(zeroBlock, PaddingMode.None);
        byte[][] LTable = new byte[m][];
        byte[] Li = (byte[])L.Clone();
        for (int j = 0; j < m; j++)
        {
            MultByTwo(Li);
            LTable[j] = (byte[])Li.Clone();
        }

        // Step 1: C[j] = AES_dir(P[j] XOR LTable[j])
        byte[] tmp = new byte[BlockSize];
        for (int j = 0; j < m; j++)
        {
            XorBlockSrc(tmp, data, j * BlockSize, LTable[j]);
            byte[] enc = AesBlock(aes, tmp, forEncrypt);
            Array.Copy(enc, 0, C, j * BlockSize, BlockSize);
        }

        // Step 2: MP = C[0] XOR T XOR C[1] XOR ... XOR C[m-1]
        byte[] MP = new byte[BlockSize];
        XorBlockSrc(MP, C, 0, tweak);
        for (int j = 1; j < m; j++)
            XorBlockAt(MP, C, j * BlockSize);

        // Step 3: MC = AES_dir(MP),  M = MP XOR MC
        byte[] MC = AesBlock(aes, MP, forEncrypt);
        byte[] M = new byte[BlockSize];
        XorBlockSrc(M, MP, 0, MC);

        // Step 4: for j=1..m-1: M = 2*M; C[j] ^= M
        byte[] Mv = (byte[])M.Clone();
        for (int j = 1; j < m; j++)
        {
            MultByTwo(Mv);
            XorBlockAt(C, j * BlockSize, Mv);
        }

        // Step 5: CCC1 = MC XOR T XOR XOR(C[j] for j=1..m-1); copy to C[0]
        byte[] CCC1 = new byte[BlockSize];
        XorBlockSrc(CCC1, MC, 0, tweak);
        for (int j = 1; j < m; j++)
            XorBlockAt(CCC1, C, j * BlockSize);
        Array.Copy(CCC1, 0, C, 0, BlockSize);

        // Step 6: C[j] = AES_dir(C[j]) XOR LTable[j]
        for (int j = 0; j < m; j++)
        {
            byte[] blk = C[(j * BlockSize)..((j + 1) * BlockSize)];
            byte[] enc = AesBlock(aes, blk, forEncrypt);
            for (int k = 0; k < BlockSize; k++)
                C[j * BlockSize + k] = (byte)(enc[k] ^ LTable[j][k]);
        }

        return C;
    }

    // GF(2^128) multiply by 2 — little-endian (index 0 = LSB byte, index 15 = MSB byte)
    private static void MultByTwo(byte[] v)
    {
        byte[] tmp = new byte[16];
        int highBit = v[15] >> 7;
        tmp[0] = (byte)(2 * v[0]);
        tmp[0] ^= (byte)(135 & (-highBit));
        for (int j = 1; j < 16; j++)
        {
            tmp[j] = (byte)(2 * v[j]);
            tmp[j] += (byte)(v[j - 1] >> 7);
        }
        Array.Copy(tmp, v, 16);
    }

    private static byte[] AesBlock(Aes aes, byte[] block, bool forEncrypt) =>
        forEncrypt
            ? aes.EncryptEcb(block, PaddingMode.None)
            : aes.DecryptEcb(block, PaddingMode.None);

    private static void XorBlockSrc(byte[] dst, byte[] src, int srcOffset, byte[] other)
    {
        for (int i = 0; i < BlockSize; i++)
            dst[i] = (byte)(src[srcOffset + i] ^ other[i]);
    }

    // dst ^= src[srcOffset..]
    private static void XorBlockAt(byte[] dst, byte[] src, int srcOffset)
    {
        for (int i = 0; i < BlockSize; i++)
            dst[i] ^= src[srcOffset + i];
    }

    // dst[dstOffset..] ^= xorWith
    private static void XorBlockAt(byte[] dst, int dstOffset, byte[] xorWith)
    {
        for (int i = 0; i < BlockSize; i++)
            dst[dstOffset + i] ^= xorWith[i];
    }
}
