using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Zyborg.Lockbox
{
    public static class MemUtil
    {
        public static bool AreEqual(this byte[] a, byte[] b)
            => a.SequenceEqual(b);

        public static byte[] ToUTF8(this string s)
            => Encoding.UTF8.GetBytes(s);

        public static string FromUTF8(this byte[] b)
            => Encoding.UTF8.GetString(b);

        public static string ToBase64(this byte[] b)
            => Convert.ToBase64String(b);
        
        public static byte[] FromBase64(this string s)
            => Convert.FromBase64String(s);

        public static void ApplyXor(this ReadOnlySpan<byte> data, ReadOnlySpan<byte> xor, Span<byte> result)
        {
            for (var i = 0; i < result.Length; ++i)
            {
                result[i] = (byte)(data[i % data.Length] ^ xor[i % xor.Length]);
            }
        }

        public static byte[] ApplyXor(this ReadOnlySpan<byte> data, ReadOnlySpan<byte> xor)
        {
            var result = new byte[data.Length];
            ApplyXor(data, xor, result);
            return result;
        }

        public static byte[] ComputeSHA1(this byte[] data)
        {
            using (var sha = SHA1.Create())
            {
                return sha.ComputeHash(data);
            }
        }
    }
}