using System;
using System.IO;

namespace Confuzzle
{
    /// <summary>
    /// A simple stream that can read Base64-encoded data.
    /// </summary>
    class Base64Reader : Stream
    {
        private static readonly byte[] DecodeMap = new byte[] { 
            //_0    _1    _2    _3    _4    _5    _6    _7    _8    _9    _A    _B    _C    _D    _E    _F
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEE, 0xEE, 0xFF, 0xFF, 0xEE, 0xFF, 0xFF,  // 0_
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 1_
            0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,  // 2_
            0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xDD, 0xFF, 0xFF,  // 3_
            0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,  // 4_
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 5_
            0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,  // 6_
            0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 7_
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 8_
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 9_
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // A_
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // B_
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // C_
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // D_
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // E_
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // F_
        };

        private Stream _stream;
        private bool _leaveOpen;
        private uint _bits = 0;
        private int _bitsRemaining = 0;

        public Base64Reader(Stream stream, bool leaveOpen = false)
        {
            _stream = stream;
            _leaveOpen = leaveOpen;
        }

        public override bool CanRead
        {
            get { return _stream.CanRead; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return false; }
        }

        public override long Length
        {
            get { return _stream.Length; }
        }

        public override long Position
        {
            get { return _stream.Position; }
            set { throw new NotSupportedException(); }
        }

        public override void Flush()
        {
            _stream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            // Try to fill as much of the buffer as possible.
            for (var index = 0; index < count; ++index)
            {
                // Ensure there's at least one byte of data in the buffer.
                if (!FillBuffer())
                    return index;

                // Read the high byte from the buffer.
                _bitsRemaining -= 8;
                buffer[offset + index] = (byte)((_bits >> _bitsRemaining) & 0xFF);
            }

            return count;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_stream != null)
                {
                    _stream.Flush();

                    if (!_leaveOpen)
                        _stream.Dispose();
                }

                _stream = null;
            }

            base.Dispose(disposing);
        }

        private bool FillBuffer()
        {
            // Read up to 24 bits of data at a time.
            int b = 0;
            while (_bitsRemaining < 24 && (b = _stream.ReadByte()) >= 0)
            {
                // Get the value that the byte maps to.
                var byteValue = DecodeMap[b];

                // Check for invalid Base64 characters.
                if (byteValue == 0xFF)
                    throw new InvalidDataException("Data is not Base64-encoded.");

                // Check for ignored characters (e.g. whitespace).
                if (byteValue == 0xEE)
                    continue;

                // Check for terminating characters ('=').
                if (byteValue == 0xDD)
                {
                    // You could get up to 2 '=' signs at the end of the file. If input seeking is possible, check the
                    // next character and see if it needs to be skipped too.
                    if (_stream.CanSeek)
                    {
                        b = _stream.ReadByte();
                        if (b > 0 && DecodeMap[b] != 210)
                            _stream.Seek(-1, SeekOrigin.Current);
                    }

                    break;
                }

                // Add bits to the buffer.
                _bits = (_bits << 6) | byteValue;
                _bitsRemaining += 6;
            }

            // Is there a full byte of data remaining?
            return _bitsRemaining >= 8;
        }
    }

    /// <summary>
    /// A simple stream that can write Base64-encoded data.
    /// </summary>
    class Base64Writer : Stream
    {
        private static readonly byte[] EncodeMap = new byte[] {
            // A-Z
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
            // a-z
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
            // 0-9
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            // +     /
            0x2B, 0x2F
        };

        private Stream _stream;
        private bool _leaveOpen;
        private uint _bits = 0;
        private int _bitsRemaining = 0;

        public Base64Writer(Stream stream, bool leaveOpen = false)
        {
            _stream = stream;
            _leaveOpen = leaveOpen;
        }

        public override bool CanRead
        {
            get { return false; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return _stream.CanWrite; }
        }

        public override long Length
        {
            get { return _stream.Length; }
        }

        public override long Position
        {
            get { return _stream.Position; }
            set { throw new NotSupportedException(); }
        }

        public override void Flush()
        {
            _stream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            // Write chunks of data at a time.
            var output = new byte[256];
            var outputLen = 0;

            // Process all input.
            for (var index = 0; index < count; ++index)
            {
                // Push the current byte into the buffer.
                _bits = (_bits << 8) | buffer[offset + index];
                _bitsRemaining += 8;

                // While values can be read from the buffer...
                int value;
                while (GetValue(out value))
                {
                    // Add the Base64 byte that the value maps to.
                    output[outputLen++] = EncodeMap[value];

                    // Write out the buffer when it's full.
                    if (outputLen >= output.Length)
                    {
                        _stream.Write(output, 0, outputLen);
                        outputLen = 0;
                    }
                }
            }

            // Write out any remaining data in the buffer.
            if (outputLen > 0)
                _stream.Write(output, 0, outputLen);
        }

        public void Finish()
        {
            // Special finalization only needed if there are bits to write.
            if (_bitsRemaining == 0)
                return;

            // Prepare to process the final bytes.
            var output = new byte[4] { 0x3D, 0x3D, 0x3D, 0x3D };
            var outputLen = 0;
            int value;
            
            // Get any full bytes remaining.
            while (GetValue(out value))
                output[outputLen++] = EncodeMap[value];

            // Any remaining partial characters need special treatment.
            if (_bitsRemaining > 0)
            {
                // The remaining bits for the high bits of an encoded value.
                _bits <<= 6 - _bitsRemaining;
                output[outputLen++] = EncodeMap[_bits & 0x3F];

                // Add enough equals signs to pad the length.
                // This happens to be 1x equals sign for every additional 2 bits needed to make the full 6 bits per
                // character.
                for (var counter = _bitsRemaining; counter < 6; counter += 2)
                    ++outputLen;
            }

            // Write the final bytes.
            _stream.Write(output, 0, outputLen);

            // Clear out the buffer.
            _bitsRemaining = 0;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_stream != null)
                {
                    Finish();
                    _stream.Flush();

                    if (!_leaveOpen)
                        _stream.Dispose();
                }

                _stream = null;
            }

            base.Dispose(disposing);
        }

        private bool GetValue(out int value)
        {
            var shift = _bitsRemaining - 6;

            if (shift < 0)
            {
                value = 0;
                return false;
            }

            var mask = 0x3FU << shift;
            value = (int)((_bits & mask) >> shift);

            _bitsRemaining -= 6;
            return true;
        }
    }
}
