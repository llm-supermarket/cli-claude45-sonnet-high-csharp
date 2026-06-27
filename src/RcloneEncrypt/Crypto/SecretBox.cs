using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace RcloneEncrypt.Crypto;

// NaCl SecretBox using XSalsa20 + Poly1305
internal static class SecretBox
{
    internal const int KeySize = 32;
    internal const int NonceSize = 24;
    internal const int Overhead = 16; // Poly1305 tag

    private static readonly uint[] Sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    // Returns tag (16 bytes) || ciphertext
    internal static byte[] Seal(byte[] plaintext, byte[] nonce, byte[] key)
    {
        byte[] subkey = HSalsa20(key, nonce[..16]);
        byte[] block0 = Salsa20Block(subkey, nonce[16..24], 0);
        byte[] polyKey = block0[..32];

        // encrypt: message starts at keystream offset 32 (still in block 0)
        byte[] ciphertext = XorWithKeystream(subkey, nonce[16..24], plaintext, keyStreamStart: 32);

        byte[] tag = ComputePoly1305(polyKey, ciphertext);

        byte[] result = new byte[Overhead + ciphertext.Length];
        tag.CopyTo(result, 0);
        ciphertext.CopyTo(result, Overhead);
        return result;
    }

    // Returns decrypted plaintext, throws on MAC failure
    internal static byte[] Open(ReadOnlySpan<byte> box, byte[] nonce, byte[] key)
    {
        if (box.Length < Overhead)
            throw new CryptographicException("Box too short");

        byte[] subkey = HSalsa20(key, nonce[..16]);
        byte[] block0 = Salsa20Block(subkey, nonce[16..24], 0);
        byte[] polyKey = block0[..32];

        byte[] tag = box[..Overhead].ToArray();
        byte[] ciphertext = box[Overhead..].ToArray();

        byte[] expectedTag = ComputePoly1305(polyKey, ciphertext);
        if (!CryptoEquals(tag, expectedTag))
            throw new CryptographicException("MAC verification failed - wrong password or corrupted data");

        return XorWithKeystream(subkey, nonce[16..24], ciphertext, keyStreamStart: 32);
    }

    // XSalsa20: derive subkey using HSalsa20 from key + first 16 bytes of nonce
    private static byte[] HSalsa20(byte[] key, byte[] nonce16)
    {
        uint[] state =
        [
            Sigma[0], LoadLE32(key, 0), LoadLE32(key, 4), LoadLE32(key, 8),
            LoadLE32(key, 12), Sigma[1], LoadLE32(nonce16, 0), LoadLE32(nonce16, 4),
            LoadLE32(nonce16, 8), LoadLE32(nonce16, 12), Sigma[2], LoadLE32(key, 16),
            LoadLE32(key, 20), LoadLE32(key, 24), LoadLE32(key, 28), Sigma[3]
        ];

        uint[] x = Salsa20Permute(state);

        // HSalsa20 output: words 0,5,10,15,6,7,8,9 (WITHOUT adding initial state)
        byte[] output = new byte[32];
        StoreLE32(output, 0, x[0]);
        StoreLE32(output, 4, x[5]);
        StoreLE32(output, 8, x[10]);
        StoreLE32(output, 12, x[15]);
        StoreLE32(output, 16, x[6]);
        StoreLE32(output, 20, x[7]);
        StoreLE32(output, 24, x[8]);
        StoreLE32(output, 28, x[9]);
        return output;
    }

    private static byte[] Salsa20Block(byte[] key, byte[] nonce8, ulong counter)
    {
        uint[] state =
        [
            Sigma[0], LoadLE32(key, 0), LoadLE32(key, 4), LoadLE32(key, 8),
            LoadLE32(key, 12), Sigma[1], LoadLE32(nonce8, 0), LoadLE32(nonce8, 4),
            (uint)(counter & 0xFFFFFFFF), (uint)(counter >> 32), Sigma[2], LoadLE32(key, 16),
            LoadLE32(key, 20), LoadLE32(key, 24), LoadLE32(key, 28), Sigma[3]
        ];

        uint[] x = Salsa20Permute(state);

        byte[] block = new byte[64];
        for (int i = 0; i < 16; i++)
            StoreLE32(block, i * 4, x[i] + state[i]); // add initial state
        return block;
    }

    private static byte[] XorWithKeystream(byte[] key, byte[] nonce8, byte[] input, int keyStreamStart)
    {
        byte[] output = new byte[input.Length];

        ulong blockIdx = (ulong)(keyStreamStart / 64);
        int byteInBlock = keyStreamStart % 64;
        int inputOffset = 0;

        while (inputOffset < input.Length)
        {
            byte[] block = Salsa20Block(key, nonce8, blockIdx);
            for (int i = byteInBlock; i < 64 && inputOffset < input.Length; i++, inputOffset++)
                output[inputOffset] = (byte)(input[inputOffset] ^ block[i]);
            byteInBlock = 0;
            blockIdx++;
        }

        return output;
    }

    // 20 rounds of Salsa20 (column + row double-rounds) — returns permuted state WITHOUT adding initial
    private static uint[] Salsa20Permute(uint[] s)
    {
        uint[] x = (uint[])s.Clone();

        for (int i = 0; i < 10; i++)
        {
            // column rounds
            x[4]  ^= RotL(x[0]  + x[12], 7);  x[8]  ^= RotL(x[4]  + x[0],  9);
            x[12] ^= RotL(x[8]  + x[4],  13); x[0]  ^= RotL(x[12] + x[8],  18);
            x[9]  ^= RotL(x[5]  + x[1],  7);  x[13] ^= RotL(x[9]  + x[5],  9);
            x[1]  ^= RotL(x[13] + x[9],  13); x[5]  ^= RotL(x[1]  + x[13], 18);
            x[14] ^= RotL(x[10] + x[6],  7);  x[2]  ^= RotL(x[14] + x[10], 9);
            x[6]  ^= RotL(x[2]  + x[14], 13); x[10] ^= RotL(x[6]  + x[2],  18);
            x[3]  ^= RotL(x[15] + x[11], 7);  x[7]  ^= RotL(x[3]  + x[15], 9);
            x[11] ^= RotL(x[7]  + x[3],  13); x[15] ^= RotL(x[11] + x[7],  18);
            // row rounds
            x[1]  ^= RotL(x[0]  + x[3],  7);  x[2]  ^= RotL(x[1]  + x[0],  9);
            x[3]  ^= RotL(x[2]  + x[1],  13); x[0]  ^= RotL(x[3]  + x[2],  18);
            x[6]  ^= RotL(x[5]  + x[4],  7);  x[7]  ^= RotL(x[6]  + x[5],  9);
            x[4]  ^= RotL(x[7]  + x[6],  13); x[5]  ^= RotL(x[4]  + x[7],  18);
            x[11] ^= RotL(x[10] + x[9],  7);  x[8]  ^= RotL(x[11] + x[10], 9);
            x[9]  ^= RotL(x[8]  + x[11], 13); x[10] ^= RotL(x[9]  + x[8],  18);
            x[12] ^= RotL(x[15] + x[14], 7);  x[13] ^= RotL(x[12] + x[15], 9);
            x[14] ^= RotL(x[13] + x[12], 13); x[15] ^= RotL(x[14] + x[13], 18);
        }

        return x;
    }

    private static byte[] ComputePoly1305(byte[] key32, byte[] data)
    {
        var poly = new Poly1305();
        poly.Init(new KeyParameter(key32));
        poly.BlockUpdate(data, 0, data.Length);
        byte[] tag = new byte[16];
        poly.DoFinal(tag, 0);
        return tag;
    }

    private static bool CryptoEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static uint LoadLE32(byte[] buf, int offset) =>
        (uint)(buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | (buf[offset + 3] << 24));

    private static void StoreLE32(byte[] buf, int offset, uint v)
    {
        buf[offset]     = (byte)v;
        buf[offset + 1] = (byte)(v >> 8);
        buf[offset + 2] = (byte)(v >> 16);
        buf[offset + 3] = (byte)(v >> 24);
    }

    private static uint RotL(uint v, int n) => (v << n) | (v >> (32 - n));
}
