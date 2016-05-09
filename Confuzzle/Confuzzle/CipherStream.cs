using System;
using System.IO;
using System.Security.Cryptography;

namespace Confuzzle
{
    /// <summary>
    ///     A filter stream that encrypts and decrypts data to/from an underlying stream.
    /// </summary>
    /// <remarks>
    ///     The encrypted data starts with a header that contains information necessary to perform the decryption.
    ///
    ///     The layout of the header is as follows:
    ///     * A 16-bit unsigned integer saying how much data is in the rest of the header.
    ///     * A 16-bit unsigned integer saying how long the nonce is.
    ///     * Variable length nonce.
    ///     * A 16-bit unsigned integer saying how long the user data (password salt) is.
    ///     * Variable length user data.
    /// </remarks>
    public class CipherStream : Stream
    {
        private const int HeaderOverhead = 2 * sizeof(ushort);

        public static RandomNumberGenerator Rng { get; set; } = new RNGCryptoServiceProvider();

        private readonly Stream _stream;
        private CtrModeTransform _ctrTransform;
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

            _ctrTransform = new CtrModeTransform(this);
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
                Rng.GetBytes(nonce);
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
                if (_ctrTransform != null)
                {
                    _ctrTransform.Dispose();
                    _ctrTransform = null;
                }
            }
        }

        private void ResetState(byte[] nonce, byte[] userData)
        {
            Nonce = nonce;
            UserData = userData ?? new byte[0];

            Key.Salt = UserData;

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
            var sizeRead = _stream.Read(buffer, offset, count);

            if (sizeRead > 0)
            {
                _ctrTransform.Transform(_position, buffer, offset, sizeRead);
                _position += sizeRead;
            }

            return sizeRead;
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

            return _position;
        }

        public override void SetLength(long value)
        {
            SetLength(_startPosition + value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            var writeBuffer = new byte[count];
            Array.Copy(buffer, offset, writeBuffer, 0, count);

            _ctrTransform.Transform(_position, writeBuffer, 0, count);

            _stream.Write(writeBuffer);

            _position += count;
        }

        #endregion
    }
}
