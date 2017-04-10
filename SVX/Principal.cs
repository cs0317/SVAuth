using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Reflection;
using Newtonsoft.Json.Linq;

namespace SVX
{
    [JsonConverter(typeof(PrincipalJsonConverter))]
    public abstract class Principal
    {
        // No other subclasses please.  If we really cared, we could define a Visit method.
        internal Principal() { }
        public override abstract bool Equals(object that);
        public override abstract int GetHashCode();

        /* We pretend to BCT that PrincipalHandles are interned, like strings.
         * And as for strings, this is convenient (and assumed by the current
         * collection stubs) but unsound if we ever call ReferenceEquals.  If we
         * ever decide on a better approach, we can apply it to all classes at
         * once. ~ t-mattmc@microsoft.com 2016-07-05 */
        [BCTOmitImplementation]
        // Careful: either argument could be null!
        public static bool operator ==(Principal left, Principal right) => Equals(left, right);
        [BCTOmitImplementation]
        public static bool operator !=(Principal left, Principal right) => !Equals(left, right);
    }

    // TODO: Do we want to discourage callers from poking at fields in
    // inappropriate ways?

    // FIXME: Currently, poirot_stubs.bpl assumes that collections compare keys
    // by reference equality, which is not right.  Our options are basically to
    // axiomatize the "equals state" of objects or implement the collections in
    // terms of Equals and GetHashCode (terrible dynamic dispatch and needs
    // stubs for system types).

    public class PrincipalJsonConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return typeof(Principal).IsAssignableFrom(objectType);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            // I guess this is the converter's responsibility?
            if (reader.TokenType == JsonToken.Null)
                return null;

            JObject jobject = JObject.Load(reader);
            string name = jobject.Value<string>("name");
            if (name != null)
                return Entity.Of(name);
            else
                return Channel.Of(
                    // XXX Inefficient; learn if there is a better way to use this API.
                    serializer.Deserialize<Entity>(new JTokenReader(jobject["issuer"])),
                    jobject.Value<string>("id"));
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            throw new NotImplementedException();
        }

        public override bool CanWrite => false;
    }

    [JsonConverter(typeof(PrincipalJsonConverter))]
    public class Entity : Principal
    {
        // The naming conventions are not finalized, but for now we are using
        // hostnames and some other special formats that cannot be confused with
        // hostnames.  (Want to introduce actual data structures for those
        // formats?)
        public readonly string name;

        private Entity(string name)
        {
            if (name == null)
                throw new ArgumentNullException();
            this.name = name;
        }

        [BCTOmitImplementation]
        public static Entity Of(string name)
        {
            return new Entity(name);
        }

        public override bool Equals(object that)
        {
            var thatPrincipal = that as Entity;
            return thatPrincipal != null && name == thatPrincipal.name;
        }
        public override int GetHashCode() => Hasher.Start.With(name.GetHashCode());

        public override string ToString() => name;
    }

    /* A PrincipalFacet is a placeholder identifier automatically assigned to a
     * principal whose true identity is not immediately known. */
    [JsonConverter(typeof(PrincipalJsonConverter))]
    public class Channel : Principal
    {
        /* This is mainly here for diagnostic purposes.  If all trusted
         * principals generate the ID randomly, we can assume there are no
         * collisions among the facets they generate, and we can't assume
         * anything about what untrusted principals do anyway. */
        public readonly Entity issuer;
        // Should be generated randomly.
        public readonly string id;

        private Channel(Entity issuer, string id)
        {
            if (issuer == null || id == null)
                throw new ArgumentNullException();
            this.issuer = issuer;
            this.id = id;
        }

        [BCTOmitImplementation]
        public static Channel Of(Entity issuer, string id)
        {
            return new Channel(issuer, id);
        }

        public static Channel GenerateNew(Entity issuer)
        {
            return new Channel(issuer, Utils.RandomIdString());
        }

        public override bool Equals(object that)
        {
            var thatFacet = that as Channel;
            return thatFacet != null && issuer == thatFacet.issuer && id == thatFacet.id;
        }
        public override int GetHashCode() => Hasher.Start.With(issuer.GetHashCode()).With(id.GetHashCode());

        public override string ToString() => "[" + id + "@" + issuer + "]";
    }

}
