using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Confuzzle
{
    class KeyStretcher : Rfc2898DeriveBytes
    {
        public const int DefaultIterationCount = 10000;
        public const int DefaultSaltSize = 16;

        public static RandomNumberGenerator Rng { get; set; } = new RNGCryptoServiceProvider();

        public KeyStretcher(string password)
            : base(password, GenerateSalt(DefaultSaltSize), DefaultIterationCount)
        {
        }

        public KeyStretcher(string password, int iterationCount)
            : base(password, GenerateSalt(DefaultSaltSize), iterationCount)
        {
        }

        public KeyStretcher(string password, byte[] salt)
            : base(password, salt, DefaultIterationCount)
        {
        }

        public KeyStretcher(string password, byte[] salt, int iterationCount)
            : base(password, salt, iterationCount)
        {
        }

        public KeyStretcher(byte[] password)
            : base(password, GenerateSalt(DefaultSaltSize), DefaultIterationCount)
        {
        }

        public KeyStretcher(byte[] password, int iterationCount)
            : base(password, GenerateSalt(DefaultSaltSize), iterationCount)
        {
        }

        public KeyStretcher(byte[] password, byte[] salt)
            : base(password, salt, DefaultIterationCount)
        {
        }

        public KeyStretcher(byte[] password, byte[] salt, int iterationCount)
            : base(password, salt, iterationCount)
        {
        }

        public static byte[] GenerateSalt(int saltSize)
        {
            if (saltSize < 8)
                throw new ArgumentException("The specified salt size is smaller than 8 bytes.", nameof(saltSize));

            var salt = new byte[saltSize];
            Rng.GetBytes(salt);
            return salt;
        }

        public byte[] GetKeyBytes(int keySizeBits)
        {
            if (keySizeBits % 8 != 0)
                throw new ArgumentException("Key size must be a multiple of 8 bits.", nameof(keySizeBits));

            return GetBytes(keySizeBits / 8);
        }

        public byte[] GetKeyBytes(SymmetricAlgorithm algorithm)
        {
            return GetKeyBytes(algorithm, int.MaxValue);
        }

        public byte[] GetKeyBytes(SymmetricAlgorithm algorithm, int maxKeySizeBits)
        {
            var maxLegalSize = algorithm.LegalKeySizes
                .Select(ks => GetMaxKeySize(ks, maxKeySizeBits))
                .Max();

            if (maxLegalSize == 0)
                throw new ArgumentException("Maximum key size is too low.", nameof(maxKeySizeBits));

            return GetKeyBytes(maxLegalSize);
        }

        public void Reset(byte[] salt, int iterationCount)
        {
            Salt = salt;
            IterationCount = iterationCount;
            Reset();
        }

        private static int GetMaxKeySize(KeySizes keySizes, int maxSize)
        {
            for (var keySize = keySizes.MaxSize; keySize >= keySizes.MinSize; keySize -= keySizes.SkipSize)
            {
                if (keySize <= maxSize)
                    return keySize;
            }

            return 0;
        }
    }
}
