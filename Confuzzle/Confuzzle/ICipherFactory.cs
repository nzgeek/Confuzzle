using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Confuzzle
{
    public interface ICipherFactory
    {
        SymmetricAlgorithm CreateCipher();

        HashAlgorithm CreateHash();
    }
}
