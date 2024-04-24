using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionLibrary.EncryptionCode.Asymmetric
{
    internal class MyRandom
    {
        private ulong seed;

        public MyRandom(ulong seed)
        {
            this.seed = seed;
        }

        // Generate a random integer between minValue (inclusive) and maxValue (exclusive)
        public int Next(int minValue, int maxValue)
        {
            if (minValue >= maxValue)
            {
                throw new ArgumentException("minValue must be less than maxValue");
            }

            ulong range = (ulong)(maxValue - minValue);
            ulong next = NextUInt64();
            ulong scaled = (next * range) >> 64;
            return (int)(minValue + (long)scaled);
        }

        // Generate a random integer
        public int Next()
        {
            return (int)(NextUInt64() >> 1);
        }

        // Generate a random double between 0.0 and 1.0
        public double NextDouble()
        {
            return (double)(NextUInt64() >> 11) * (1.0 / (1UL << 53));
        }

        // Generate a random unsigned 64-bit integer
        private ulong NextUInt64()
        {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            return seed * 2685821657736338717UL;
        }

        // Generate a random byte array of the specified length
        public byte[] NextBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            for (int i = 0; i < length; i++)
            {
                randomBytes[i] = (byte)Next(0, 256); // Generate a random byte (0 to 255)
            }
            return randomBytes;
        }
    }

}