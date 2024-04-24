using System.Numerics;
using System.Text;

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
            int maxBlockSize = (BitLength(n) + 7) / 8 - 11;
            List<byte[]> encryptedBlocks = new List<byte[]>();

            for (int i = 0; i < data.Length; i += maxBlockSize)
            {
                int blockSize = Math.Min(maxBlockSize, data.Length - i);
                byte[] block = new byte[blockSize];
                Array.Copy(data, i, block, 0, blockSize);
                byte[] encryptedBlock = RSAEP(block);
                encryptedBlocks.Add(encryptedBlock);
            }

            return encryptedBlocks.SelectMany(x => x).ToArray();
        }

        public byte[] Decrypt(byte[] data)
        {
            int maxBlockSize = (BitLength(n) + 7) / 8;
            List<byte[]> decryptedBlocks = new List<byte[]>();

            for (int i = 0; i < data.Length; i += maxBlockSize)
            {
                int blockSize = Math.Min(maxBlockSize, data.Length - i);
                byte[] block = new byte[blockSize];
                Array.Copy(data, i, block, 0, blockSize);
                byte[] decryptedBlock = RSADP(block);
                decryptedBlocks.Add(decryptedBlock);
            }

            return decryptedBlocks.SelectMany(x => x).ToArray();
        }
        public byte[] Sign(byte[] data)
        {
            int maxBlockSize = (BitLength(n) + 7) / 8 - 11;
            List<byte[]> encryptedBlocks = new List<byte[]>();

            for (int i = 0; i < data.Length; i += maxBlockSize)
            {
                int blockSize = Math.Min(maxBlockSize, data.Length - i);
                byte[] block = new byte[blockSize];
                Array.Copy(data, i, block, 0, blockSize);
                byte[] encryptedBlock = RSADP(block);
                encryptedBlocks.Add(encryptedBlock);
            }

            return encryptedBlocks.SelectMany(x => x).ToArray();
        }

        public byte[] Verify(byte[] data)
        {
            int maxBlockSize = (BitLength(n) + 7) / 8;
            List<byte[]> decryptedBlocks = new List<byte[]>();

            for (int i = 0; i < data.Length; i += maxBlockSize)
            {
                int blockSize = Math.Min(maxBlockSize, data.Length - i);
                byte[] block = new byte[blockSize];
                Array.Copy(data, i, block, 0, blockSize);
                byte[] decryptedBlock = RSAEP(block);
                decryptedBlocks.Add(decryptedBlock);
            }

            return decryptedBlocks.SelectMany(x => x).ToArray();
        }
        private byte[] RSAEP(byte[] data)
        {
            BigInteger m = new BigInteger(data.Reverse().ToArray());
            BigInteger c = BigInteger.ModPow(m, e, n);
            byte[] result = c.ToByteArray();
            Array.Reverse(result);
            return result;
        }

        private byte[] RSADP(byte[] data)
        {
            BigInteger c = new BigInteger(data.Reverse().ToArray());
            BigInteger m = BigInteger.ModPow(c, d, n);
            byte[] result = m.ToByteArray();
            Array.Reverse(result);
            return result;
        }

        private int BitLength(BigInteger value)
        {
            return (int)Math.Ceiling(BigInteger.Log(value + 1, 2));
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
        public void SetPublicKey(BigInteger modulus, BigInteger exponent)
        {
            n = modulus;
            e = exponent;
        }

        // Setter for private key (n, d)
        public void SetPrivateKey(BigInteger modulus, BigInteger exponent)
        {
            n = modulus;
            d = exponent;
        }

        // Method to convert PEM formatted string to BigInteger for n and e
        private void PemToPublicKey(string publicKeyPem)
        {
            string[] lines = publicKeyPem.Split('\n');
            foreach (string line in lines)
            {
                if (line.StartsWith("n:"))
                {
                    n = BigInteger.Parse(line.Substring(2));
                }
                else if (line.StartsWith("e:"))
                {
                    e = BigInteger.Parse(line.Substring(2));
                }
            }
        }

        // Method to convert PEM formatted string to BigInteger for n and d
        private void PemToPrivateKey(string privateKeyPem)
        {
            string[] lines = privateKeyPem.Split('\n');
            foreach (string line in lines)
            {
                if (line.StartsWith("n:"))
                {
                    n = BigInteger.Parse(line.Substring(2));
                }
                else if (line.StartsWith("d:"))
                {
                    d = BigInteger.Parse(line.Substring(2));
                }
            }
        }

        // Method to generate PEM representation of the public key (n, e)
        public string GetPublicKeyPem()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PUBLIC KEY-----");
            sb.AppendLine($"n:{n}");
            sb.AppendLine($"e:{e}");
            sb.AppendLine("-----END PUBLIC KEY-----");
            return sb.ToString();
        }

        // Method to generate PEM representation of the private key (n, d)
        public string GetPrivateKeyPem()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PRIVATE KEY-----");
            sb.AppendLine($"n:{n}");
            sb.AppendLine($"d:{d}");
            sb.AppendLine("-----END PRIVATE KEY-----");
            return sb.ToString();
        }
    }
}

