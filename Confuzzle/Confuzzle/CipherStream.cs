using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Confuzzle
{
    /**
     * The layout of the stream header is:
     * 
     *      struct StreamHeader
     *      {
     *          ushort headerDataLength;
     *     
     *          ushort nonceLength;
     *          byte[] nonce;
     *     
     *          ushort userDataLength;
     *          byte[] userData;
     *      }
     * 
     * The headerDataLength field includes the 4 bytes used to hold nonceLength and userDataLength.
     **/



    class CipherStream : Stream
    {
        private const int HeaderOverhead = 2 * sizeof(ushort);

        private static readonly RandomNumberGenerator _rng = new RNGCryptoServiceProvider();

        private readonly Stream _stream;
        private ICryptoTransform _encryptor;
        private byte[] _ctrBlock;
        private long _startPosition;
        private long _position;

        public static CipherStream Create(Stream stream, KeyStretcher key, ICipherFactory cipherFactory = null, byte[] nonce = null)
        {
            var ctrStream = new CipherStream(stream, cipherFactory, key);
            ctrStream.SetupParameters(key.Salt, nonce);
            return ctrStream;
        }

        public static CipherStream Create(Stream stream, string password, ICipherFactory cipherFactory = null, byte[] nonce = null)
        {
            var key = new KeyStretcher(password);
            var ctrStream = new CipherStream(stream, cipherFactory, key);
            ctrStream.SetupParameters(key.Salt, nonce);
            return ctrStream;
        }

        public static CipherStream Open(Stream stream, KeyStretcher key, ICipherFactory cipherFactory = null)
        {
            var ctrStream = new CipherStream(stream, cipherFactory, key);
            ctrStream.LoadParameters();
            return ctrStream;
        }

        public static CipherStream Open(Stream stream, string password, ICipherFactory cipherFactory = null)
        {
            var key = new KeyStretcher(password);
            var ctrStream = new CipherStream(stream, cipherFactory, key);
            ctrStream.LoadParameters();
            return ctrStream;
        }

        public CipherStream(Stream stream, ICipherFactory cipherFactory, KeyStretcher key)
        {
            _stream = stream;
            CipherFactory = cipherFactory ?? Confuzzle.CipherFactory.Default;
            Key = key;

            using (var cipher = CipherFactory.CreateCipher())
                BlockLength = cipher.BlockSize / 8;
        }

        internal int BlockLength { get; }

        internal ICipherFactory CipherFactory { get; }

        internal KeyStretcher Key { get; }

        public int MinNonceLength => BlockLength / 2;

        public int MaxNonceLength => BlockLength;

        public byte[] Nonce { get; private set; }

        public byte[] UserData { get; private set; }

        public void LoadParameters()
        {
            // Save the start position in case of errors.
            var startPosition = _stream.CanSeek ? _stream.Position : 0;

            try
            {
                // Read the header length and validate it.
                int headerLength = _stream.ReadUShort();
                if (headerLength < HeaderOverhead + MinNonceLength)
                    throw new InvalidDataException("Stream header is invalid.");

                // Read the nonce length and validate it.
                int nonceLength = _stream.ReadUShort();
                if ((HeaderOverhead / 2) + nonceLength > headerLength)
                    throw new InvalidDataException("Stream header is invalid.");
                if (nonceLength < MinNonceLength || nonceLength > MaxNonceLength)
                    throw new InvalidDataException("Stream contains invalid nonce.");

                // Read the nonce.
                var nonce = _stream.ReadExact(nonceLength);

                // Read the user data length and validate it.
                int userDataLength = _stream.ReadUShort();
                if (HeaderOverhead + nonceLength + userDataLength != headerLength)
                    throw new InvalidDataException("Stream header is invalid.");

                // Read the user data.
                var userData = _stream.ReadExact(userDataLength);

                ResetState(nonce, userData);
            }
            catch
            {
                // If the stream is seekable, try to return to the starting position.
                if (_stream.CanSeek)
                {
                    try { _stream.Position = startPosition; } catch {}
                }

                // Re-throw the exception.
                throw;
            }
        }

        public void SetupParameters(byte[] userData = null, byte[] nonce = null)
        {
            if (userData != null)
            {
                // The maximum user data length is limited by the header format and the minimum nonce length.
                if (HeaderOverhead + MinNonceLength + userData.Length > ushort.MaxValue)
                {
                    int maxUserDataLength = 0xFFFF - (HeaderOverhead + MinNonceLength);
                    throw new ArgumentException($"User data cannot exceed {maxUserDataLength} bytes.", nameof(userData));
                }
            }
            else
            {
                userData = new byte[0];
            }

            // Ensure that there is a valid nonce, and that it's an acceptable length.
            if (nonce != null)
            {
                if (nonce.Length < MinNonceLength || nonce.Length > MaxNonceLength)
                    throw new ArgumentException($"Nonce must be between {MinNonceLength} and {MaxNonceLength} bytes.");

                // The maximum user data length is limited by the header format and the nonce length.
                if (HeaderOverhead + nonce.Length + userData.Length > ushort.MaxValue)
                {
                    int maxUserDataLength = 0xFFFF - (HeaderOverhead + nonce.Length);
                    throw new ArgumentException($"User data cannot exceed {maxUserDataLength} bytes.", nameof(userData));
                }
            }
            else
            {
                // The nonce will be as long as possible, up to the maximum length.
                // It will always be at least the minimum length, due to an earlier check.
                int availableNonceLength = 0xFFFF - (userData.Length + 4);
                nonce = new byte[Math.Min(availableNonceLength, MaxNonceLength)];
                _rng.GetBytes(nonce);
            }

            // Write the parameters to the stream.
            _stream.WriteUShort((ushort)(HeaderOverhead + nonce.Length + userData.Length));
            _stream.WriteUShort((ushort)(nonce.Length));
            _stream.Write(nonce);
            _stream.WriteUShort((ushort)userData.Length);
            _stream.Write(userData);

            ResetState(nonce, userData);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                if (_encryptor != null)
                    _encryptor.Dispose();
                _encryptor = null;


            }
        }

        private byte[] CreateCtrBlock(long position)
        {
            // Convert the block number to a series of bytes, most significant byte first.
            var blockNumber = (position / BlockLength) + 1;
            var blockNumberBytes = BitConverter.GetBytes(blockNumber);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(blockNumberBytes);

            // Allocate a new counter block.
            var ctrSeed = new byte[BlockLength];
            // Copy in the nonce.
            Array.Copy(Nonce, ctrSeed, Nonce.Length);
            // Copy in the block number bytes using XOR. Depending on the length of the nonce, this might alter some
            // of the nonce bits.
            for (var byteIndex = 0; byteIndex < blockNumberBytes.Length && byteIndex < ctrSeed.Length; ++byteIndex)
                ctrSeed[BlockLength - blockNumberBytes.Length + byteIndex] ^= blockNumberBytes[byteIndex];

            // Ensure there's an encryptor.
            if (_encryptor == null)
                _encryptor = CreateEncryptor();

            // Encrypt the block using the encryptor.
            var ctrBlock = new byte[BlockLength];
            _encryptor.TransformBlock(ctrSeed, 0, ctrSeed.Length, ctrBlock, 0);
            return ctrBlock;
        }

        private byte[] CreateIV()
        {
            using (var hashFunction = CipherFactory.CreateHash())
            {
                hashFunction.TransformBlock(Nonce, 0, Nonce.Length, Nonce, 0);
                hashFunction.TransformFinalBlock(UserData, 0, UserData.Length);

                var hash = hashFunction.Hash;

                var iv = new byte[BlockLength];
                for (var index = 0; index < iv.Length; index += hash.Length)
                {
                    int copySize = Math.Min(hash.Length, iv.Length - index);
                    Array.Copy(hash, 0, iv, index, copySize);
                }
                return iv;
            }
        }

        private ICryptoTransform CreateEncryptor()
        {
            var cipher = CipherFactory.CreateCipher();

            cipher.Key = Key.GetKeyBytes(cipher, 256);
            cipher.IV = CreateIV();
            cipher.Mode = CipherMode.ECB;
            cipher.Padding = PaddingMode.None;

            return cipher.CreateEncryptor();
        }

        private void ResetState(byte[] nonce, byte[] userData)
        {
            Nonce = nonce;
            UserData = userData;

            Key.Reset(userData, Key.IterationCount);

            if (_encryptor != null)
                _encryptor.Dispose();
            _encryptor = null;

            _ctrBlock = null;
            _startPosition = _stream.CanSeek ? _stream.Position : 0;
            _position = 0;
        }

        #region Stream implementation

        public override bool CanRead
        {
            get { return _stream.CanRead; }
        }

        public override bool CanSeek
        {
            get { return _stream.CanSeek; }
        }

        public override bool CanWrite
        {
            get { return _stream.CanWrite; }
        }

        public override long Length
        {
            get { return _stream.Length - _startPosition; }
        }

        public override long Position
        {
            get { return _stream.Position - _startPosition; }
            set { _stream.Position = _startPosition + value; }
        }

        public override void Flush()
        {
            _stream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int bytesRead = 0;
            for (; bytesRead < count; ++bytesRead)
            {
                int value = _stream.ReadByte();
                if (value < 0)
                    break;

                var ctrIndex = _position % BlockLength;
                if (_ctrBlock == null || ctrIndex == 0)
                    _ctrBlock = CreateCtrBlock(_position);

                buffer[offset + bytesRead] = (byte)((byte)value ^ _ctrBlock[ctrIndex]);

                ++_position;
            }

            return bytesRead;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (!_stream.CanSeek)
                throw new NotSupportedException("Stream is not seekable.");

            long position;

            switch (origin)
            {
                case SeekOrigin.Begin:
                    position = _stream.Seek(_startPosition + offset, SeekOrigin.Begin);
                    break;

                default:
                    position = _stream.Seek(offset, origin);
                if (position < _startPosition)
                    position = _stream.Seek(_startPosition, SeekOrigin.Begin);
                    break;
            }

            _position = position - _startPosition;
            _ctrBlock = null;

            return _position;
        }

        public override void SetLength(long value)
        {
            SetLength(_startPosition + value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            for (var index = 0; index < count; ++index)
            {
                var ctrIndex = _position % BlockLength;
                if (_ctrBlock == null || ctrIndex == 0)
                    _ctrBlock = CreateCtrBlock(_position);

                var value = buffer[offset + index] ^ _ctrBlock[ctrIndex];
                _stream.WriteByte((byte)(value));

                ++_position;
            }
        }

        #endregion
    }
}
