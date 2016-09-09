using System;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Xml.Serialization;

namespace SVX
{
    public static class Utils
    {
        public static string ToUrlSafeBase64String(byte[] data)
        {
            return Convert.ToBase64String(data).Replace('+', '-').Replace('/', '_');
        }
        // The Contains method is failing to resolve: probably some BCT or CCI
        // bug, which might be fixed in the new CCI.  This isn't reached in the
        // vProgram, so just get rid of the error for now.
        // ~ t-mattmc@microsoft.com 2016-07-05
        [BCTOmitImplementation]
        public static byte[] FromUrlSafeBase64String(string data)
        {
            if (data.Contains('+') || data.Contains('/'))
                throw new ArgumentException("Invalid url-safe base64 input");
            return Convert.FromBase64String(data.Replace('-', '+').Replace('_', '/'));
        }
        public static string RandomIdString()
        {
            return ToUrlSafeBase64String(Guid.NewGuid().ToByteArray());
        }
    }

    // We want to make this a struct, so we have to live with people being
    // able to create default instances.
    public struct Hasher
    {
        readonly int x;
        public Hasher(int x)
        {
            this.x = x;
        }
        public Hasher With(int y)
        {
            unchecked
            {
                return new Hasher(31 * x + y);
            }
        }
        // With(object o)?  But the caller might want to use a custom EqualityComparer.
        // I'd rather pay the boilerplate in the caller than try to deal with that here.
        public static implicit operator int(Hasher h)
        {
            // If we cared about good distribution (e.g., different hashes
            // for dictionaries that differ by a permutation of the values),
            // we'd apply some function to h.x here.
            return h.x;
        }

        public static readonly Hasher Start = new Hasher(17);

        [BCTOmitImplementation]
        static Hasher() { }
    }

    public static class SerializationUtils
    {
        // TODO(pmc): clean up duplicate code
        // Minor duplicate code (only two funcions) from svAuth Utils, which I think is ok.
        // Perhaps we can move some of svAuth Utils code to svX Utils code, then use the svX Utils code from svAuth
        public static JObject ReflectObject(object o)
        {
            var writer = new JTokenWriter();
            new JsonSerializer().Serialize(writer, o);
            return (JObject)writer.Token;
        }

        public static T UnreflectObject<T>(JObject jo)
        {
            return new JsonSerializer().Deserialize<T>(new JTokenReader(jo));
        }

        // Compute SHA256 hash of a string
        // https://msdn.microsoft.com/en-us/library/s02tk69a(v=vs.110).aspx
        public static String Hash(String value)
        {
            StringBuilder Sb = new StringBuilder();

            using (SHA256 hash = SHA256.Create())
            {
                Encoding enc = Encoding.UTF8;
                Byte[] result = hash.ComputeHash(enc.GetBytes(value));

                foreach (Byte b in result)
                    Sb.Append(b.ToString("x2"));
            }

            return Sb.ToString();
        }
    }
}
