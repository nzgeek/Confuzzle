using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Confuzzle
{
    internal class CtrBlock : IDisposable
    {
        private readonly CipherStream _stream;
        private readonly int _blockLength;
        private readonly int _blocksPerTransform;
        private readonly int _ctrTransformLength;

        private ICryptoTransform _cryptoTransform;
        private byte[] _ctrSeed;
        private byte[] _ctrTransform;
        private long _startBlock = -1;
        private long _endBlock = -1;

        public CtrBlock(CipherStream stream)
        {
            _stream = stream;

            _blockLength = _stream.BlockLength;
            _blocksPerTransform = 1024 / _blockLength;
            _ctrTransformLength = _blockLength * _blocksPerTransform;
        }

        public void Transform(long fromPosition, byte[] inBuffer, int inOffset, byte[] outBuffer, int outOffset, int count)
        {
            while (count > 0)
            {
                // Prepare the transformation for the current initial position.
                PrepareTransform(fromPosition);

                // Calculate where in the CTR transformation to start and how much can be processed.
                var xorIndex = (int)(fromPosition % _ctrTransformLength);
                var xorCount = Math.Min(_ctrTransformLength - xorIndex, count);

                // Do the XOR transformation based on the CTR transformation block.
                for (var index = 0; index < xorCount; ++index)
                    outBuffer[outOffset + index] = (byte)(inBuffer[inOffset + index] ^ _ctrTransform[xorIndex + index]);

                // Update the count and offsets based on the amount of data copied this round.
                fromPosition += xorCount;
                inOffset += xorCount;
                outOffset += xorCount;
                count -= xorCount;
            }
        }

        private void Initialize()
        {
            using (var cipher = _stream.CipherFactory.CreateCipher())
            {
                cipher.Mode = CipherMode.ECB;
                cipher.Padding = PaddingMode.None;

                var key = _stream.Key.GetKeyBytes(cipher, 256);
                var iv = CreateIV();

                _cryptoTransform = cipher.CreateEncryptor(key, iv);
            }

            _ctrSeed = new byte[_blockLength];
            Array.Copy(_stream.Nonce, 0, _ctrSeed, 0, Math.Min(_stream.Nonce.Length, _blockLength));

            _ctrTransform = new byte[_ctrTransformLength];
        }

        private byte[] CreateIV()
        {
            var ivSeed = new byte[_stream.Nonce.Length + _stream.UserData.Length];
            Array.Copy(_stream.Nonce, 0, ivSeed, 0, _stream.Nonce.Length);
            Array.Copy(_stream.UserData, 0, ivSeed, _stream.Nonce.Length, _stream.UserData.Length);

            using (var hashFunction = _stream.CipherFactory.CreateHash())
            {
                var hash = hashFunction.ComputeHash(ivSeed);
                Array.Clear(ivSeed, 0, ivSeed.Length);
                return hash;
            }
        }

        private void PrepareTransform(long fromPosition)
        {
            if (_cryptoTransform == null)
                Initialize();

            // Get the block number for the position. If it's within the current range, there's nothing to do.
            var blockNumber = (fromPosition / _blockLength);
            if (blockNumber <= _startBlock && blockNumber < _endBlock)
                return;

            // Calculate the start and end block numbers for the transform.
            var startBlock = (blockNumber / _blocksPerTransform) * _blocksPerTransform;
            var endBlock = startBlock + _blocksPerTransform;

            // Allocate memory for the initialization block.
            var blockInit = new byte[_ctrTransformLength];

            // Fill the initialization block in parallel.
            Parallel.For(0, _blocksPerTransform, blockIndex => {
                // Get the offsets of the first and last bytes for the block.
                var ctrFirst = blockIndex * _blockLength;
                var ctrLast = ctrFirst + _blockLength - 1;

                // Copy the seed to the block.
                Array.Copy(_ctrSeed, 0, blockInit, ctrFirst, _blockLength);

                // Calculate the counter number. It's 1-based, when everything else is 0-based.
                var ctrNumber = startBlock + blockIndex + 1;
                // XOR the counter number into the block, with the least significant byte at the end of the block.
                for (var ctrByte = 0; ctrByte < _blockLength && ctrNumber != 0; ++ctrByte, ctrNumber >>= 8)
                    blockInit[ctrLast - ctrByte] ^= (byte)(ctrNumber & 0xFF);
            });

            // Encrypt the initialization block to create the transformation block.
            _cryptoTransform.TransformBlock(blockInit, 0, _ctrTransformLength, _ctrTransform, 0);

            // Clear the initialization block.
            Array.Clear(blockInit, 0, blockInit.Length);

            // Save the start and end block numbers.
            _startBlock = startBlock;
            _endBlock = endBlock;
        }

        #region IDisposable Support

        private bool _isDisposed = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    // Free managed resources.

                    if (_cryptoTransform != null)
                    {
                        _cryptoTransform.Dispose();
                        _cryptoTransform = null;
                    }

                    if (_ctrTransform != null)
                    {
                        Array.Clear(_ctrTransform, 0, _ctrTransform.Length);
                        _ctrTransform = null;
                    }
                }

                _isDisposed = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
