using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Threading.Tasks;

namespace Confuzzle
{
    static class StreamExtensions
    {
        public static ushort ReadUShort(this Stream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var valueBytes = ReadExact(stream, sizeof(ushort));
            if (BitConverter.IsLittleEndian)
                Array.Reverse(valueBytes);

            return BitConverter.ToUInt16(valueBytes, 0);
        }

        public static byte[] Read(this Stream stream, int maxLength)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var value = new byte[maxLength];
            int sizeRead = stream.Read(value, 0, maxLength);

            if (sizeRead == 0)
                return null;

            if (sizeRead < value.Length)
                Array.Resize(ref value, sizeRead);

            return value;
        }

        public static byte[] ReadExact(this Stream stream, int length)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var value = new byte[length];
            int sizeRead = stream.Read(value, 0, length);

            if (sizeRead != length)
                throw new InvalidDataException($"Unable to read {length} bytes.");

            return value;
        }

        public static void WriteUShort(this Stream stream, ushort value)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var valueBytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(valueBytes);

            Write(stream, valueBytes);
        }

        public static void Write(this Stream stream, byte[] value)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            if (value != null)
                stream.Write(value, 0, value.Length);
        }
    }
}
