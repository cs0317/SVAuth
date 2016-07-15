using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SVX2
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
}
