using System;
using System.Numerics;

namespace EncryptionLibrary.EncryptionCode
{
    public class KeyGenerator
    {
        private Random random = new Random();

        public BigInteger GenerateKey(int keySize)
        {
            BigInteger primeNumber = GeneratePrime(keySize);
            return primeNumber;
        }

        private BigInteger GeneratePrime(int bits)
        {
            BigInteger prime;
            do
            {
                prime = GenerateRandomBigInteger(bits);
            } while (!IsProbablePrime(prime));

            return prime;
        }

        private bool IsProbablePrime(BigInteger n, int k = 5)
        {
            if (n <= 1 || n == 4)
                return false;
            if (n <= 3)
                return true;

            BigInteger d = n - 1;
            while (d % 2 == 0)
                d /= 2;

            for (int i = 0; i < k; i++)
            {
                if (!Witness(RandomBigInteger(2, n - 1), n, d))
                    return false;
            }
            return true;
        }

        private bool Witness(BigInteger a, BigInteger n, BigInteger d)
        {
            BigInteger x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1)
                return true;

            while (d != n - 1)
            {
                x = BigInteger.ModPow(x, 2, n);
                d *= 2;

                if (x == 1)
                    return false;
                if (x == n - 1)
                    return true;
            }

            return false;
        }

        private BigInteger RandomBigInteger(BigInteger min, BigInteger max)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger result;
            do
            {
                random.NextBytes(bytes);
                bytes[bytes.Length - 1] &= (byte)0x7F; // Ensure positive number
                result = new BigInteger(bytes);
            } while (result < min || result >= max);

            return result;
        }
        private BigInteger GenerateRandomBigInteger(int bits)
        {
            // Generate a random BigInteger of specified bit length
            byte[] bytes = new byte[bits / 8];
            random.NextBytes(bytes);
            bytes[bytes.Length - 1] &= 0x7F; // Ensure positive number
            return new BigInteger(bytes);
        }

    }
}
