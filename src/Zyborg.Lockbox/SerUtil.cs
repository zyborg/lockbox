using System.IO;
using System.Linq;
using Newtonsoft.Json;

namespace Zyborg.Lockbox
{
    public static class SerUtil
    {
        public static byte[] PackBytes(params byte[][] arrays)
            => JsonConvert.SerializeObject(arrays).ToUTF8();

        public static byte[][] UnpackBytes(byte[] arrays)
            => JsonConvert.DeserializeObject<byte[][]>(arrays.FromUTF8());

        public static byte[] Pack<T>(T obj)
            => JsonConvert.SerializeObject(obj).ToUTF8();

        public static T Unpack<T>(byte[] ser)
            => JsonConvert.DeserializeObject<T>(ser.FromUTF8());
    }
}