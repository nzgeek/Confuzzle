using System;
using System.Security.Cryptography;

namespace Confuzzle
{
    public interface ICipherFactory
    {
        SymmetricAlgorithm CreateCipher();

        HashAlgorithm CreateHash();
    }

    ////////////////////////////////////////////////////////////////////////////

    public class CipherFactory<TCipher, THash> : ICipherFactory
        where TCipher : SymmetricAlgorithm, new()
        where THash : HashAlgorithm, new()
    {
        public static ICipherFactory Default { get; } = new CipherFactory<TCipher, THash>();

        public SymmetricAlgorithm CreateCipher()
        {
            return new TCipher();
        }

        public HashAlgorithm CreateHash()
        {
            return new THash();
        }
    }

    ////////////////////////////////////////////////////////////////////////////

    public class CipherFactory : CipherFactory<AesManaged, SHA256CryptoServiceProvider>
    {
        public static ICipherFactory For<TCipher, THash>()
            where TCipher : SymmetricAlgorithm, new()
            where THash : HashAlgorithm, new()
        {
            return CipherFactory<TCipher, THash>.Default;
        }
    }
}
