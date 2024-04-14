using System.Numerics;
using System.Text;
using EncryptionLibrary.EncryptionCode;
namespace EncryptionLibrary.EncryptionCode.Asymmetric
{
    public class RSAalgorithm
    {
        private BigInteger n, e, d;
        KeyGenerator keyGenerator = new KeyGenerator();
        public void GenerateKeys(int keySize)
        {
            BigInteger p =  keyGenerator.GenerateKey(keySize / 2);
            BigInteger q = keyGenerator.GenerateKey(keySize / 2);

            // Calculate n and phi
            n = p * q;
            BigInteger phi = (p - 1) * (q - 1);

            // Choose e such that 1 < e < phi and e is coprime to phi
            e = ChoosePublicExponent(phi);

            // Calculate d such that (d * e) % phi == 1
            d = ModInverse(e, phi);
        }

        public void ASCIItoBigInteger(string publicKey, string privateKey)
        {
            string[] publicKeyComponents = publicKey.Split('\n');
            string[] privateKeyComponents = privateKey.Split('\n');

            // Convert ASCII to bytes
            byte[] nBytes = Encoding.ASCII.GetBytes(publicKeyComponents[0]);
            byte[] eBytes = Encoding.ASCII.GetBytes(publicKeyComponents[1]);
            byte[] dBytes = Encoding.ASCII.GetBytes(privateKeyComponents[1]);

            // Convert bytes to BigInteger
            n = new BigInteger(nBytes);
            e = new BigInteger(eBytes);
            d = new BigInteger(dBytes);
        }

        public byte[] Encrypt(byte[] data)
        {
            BigInteger plaintext = new BigInteger(data);
            BigInteger ciphertext = BigInteger.ModPow(plaintext, e, n);
            return ciphertext.ToByteArray();
        }

        public byte[] Decrypt(byte[] data)
        {
            BigInteger ciphertext = new BigInteger(data);
            BigInteger plaintext = BigInteger.ModPow(ciphertext, d, n);
            return plaintext.ToByteArray();
        }

        private BigInteger ChoosePublicExponent(BigInteger phi)
        {
            // Common choices for public exponent: 3, 65537 (0x10001), etc.
            BigInteger e = 65537;
            while (BigInteger.GreatestCommonDivisor(e, phi) != 1)
            {
                e++;
            }
            return e;
        }

        private BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }
        ///////////////////////////////////////////////////////////////////////////
        private byte[] BigIntegerToBytes(BigInteger bigInteger)
        {
            byte[] bytes = bigInteger.ToByteArray();

            // BigInteger.ToByteArray() returns the two's complement representation
            // Remove leading zero byte if present
            if (bytes[0] == 0)
            {
                byte[] trimmedBytes = new byte[bytes.Length - 1];
                Array.Copy(bytes, 1, trimmedBytes, 0, trimmedBytes.Length);
                bytes = trimmedBytes;
            }

            return bytes;
        }

        // Method to convert byte array to ASCII string
        private string BytesToAscii(byte[] bytes)
        {
            return Encoding.ASCII.GetString(bytes);
        }

        // Method to convert byte array to PEM format
        private string BytesToPem(byte[] bytes, string type)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"-----BEGIN {type}-----");

            int lineLength = 64; // Maximum line length in PEM format

            for (int i = 0; i < bytes.Length; i += lineLength)
            {
                int length = Math.Min(lineLength, bytes.Length - i);
                builder.AppendLine(Convert.ToBase64String(bytes, i, length));
            }

            builder.AppendLine($"-----END {type}-----");

            return builder.ToString();
        }

        // Method to get ASCII representation of n
        public string GetNAscii()
        {
            byte[] nBytes = BigIntegerToBytes(n);
            return BytesToAscii(nBytes);
        }

        // Method to get ASCII representation of e
        public string GetEAscii()
        {
            byte[] eBytes = BigIntegerToBytes(e);
            return BytesToAscii(eBytes);
        }

        // Method to get ASCII representation of d
        public string GetDAscii()
        {
            byte[] dBytes = BigIntegerToBytes(d);
            return BytesToAscii(dBytes);
        }

        // Method to get PEM representation of n
        public string GetNPem()
        {
            byte[] nBytes = BigIntegerToBytes(n);
            return BytesToPem(nBytes, "MODULUS");
        }

        // Method to get PEM representation of e
        public string GetEPem()
        {
            byte[] eBytes = BigIntegerToBytes(e);
            return BytesToPem(eBytes, "PUBLIC EXPONENT");
        }

        // Method to get PEM representation of d
        public string GetDPem()
        {
            byte[] dBytes = BigIntegerToBytes(d);
            return BytesToPem(dBytes, "PRIVATE EXPONENT");
        }
    }
}

