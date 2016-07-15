using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace SVX2
{
    // Properties of tokens:
    // - Bearer or not
    // - Authenticates SVX_MSG or not
    // - Contains the original parameters or not
    // (We are just adding support for the combinations we need in actual
    // protocols.  It's hard to know if we got everything.)

    // Why does C# require that base classes be accessible?
    [JsonConverter(typeof(SecretJsonConverter))]
    public class Secret
    {
        internal Secret() { }

        internal string secretValue;
        // Null means we are importing and haven't determined it yet.
        internal PrincipalHandle[] knownReaders;

        internal bool exportApproved;

        public static Secret Import(string secretValue)
        {
            return new Secret { secretValue = secretValue };
        }

        public string Export()
        {
            if (!exportApproved)
                throw new InvalidOperationException();
            return secretValue;
        }
    }

    // The secretValue of a PayloadSecret includes a representation of the
    // original parameters.  An explicit copy of the parameters is not exported,
    // but is kept in the PayloadSecret after generation and is extracted
    // immediately on import so it can be used by the message structure to
    // reconstruct reader lists.
    [JsonConverter(typeof(SecretJsonConverter))]
    public class PayloadSecret<TParams> : Secret
    {
        // XXX Make readonly; not a greater risk than anything else at the moment.
        public TParams theParams;

        public static new PayloadSecret<TParams> Import(string secretValue)
        {
            return new PayloadSecret<TParams> { secretValue = secretValue };
        }
    }

    // In principle, this class should not have internal access to SVX, but it's
    // not worth enforcing.
    public class SecretJsonConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(Secret) ||
                (objectType.IsConstructedGenericType && objectType.GetGenericTypeDefinition() == typeof(PayloadSecret<>));
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            // I guess this is the converter's responsibility?
            if (reader.TokenType == JsonToken.Null)
                return null;

            string secretValue = (string)reader.Value;
            if (objectType == typeof(Secret))
                return Secret.Import(secretValue);
            else
            {
                // Getting used to this by now...
                return objectType.GetMethod(nameof(PayloadSecret<object>.Import)).Invoke(null, new object[] { secretValue });
            }
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.WriteValue(((Secret)value).Export());
        }
    }

    /* A SecretGenerator should have the property that, for the purposes of our
     * model, there is no way to come up with a secretValue that passes Verify
     * for particular parameters except to get it from Generate.  Examples:
     * signatures or HMACs.  For signatures, if you have only the public key,
     * you can define a SecretGenerator where RawGenerate throws an
     * InvalidOperationException. */
    public abstract class SecretGenerator<TParams>
    {
        protected abstract string RawGenerate(TParams theParams);

        // On verification failure, this should throw an exception.  This makes
        // it easy to provide info about the nature of the failure rather than
        // just a boolean.  (The alternative would be to return a boolean and
        // log the info somewhere else.)
        protected abstract void RawVerify(TParams theParams, string secretValue);

        // NOTE: We need to pay attention to make sure that enough information
        // is recorded for a symbolic proof about the readers to go through.  At
        // minimum, that probably means the exact dynamic type of the
        // SecretGenerator so we know which override of GetReaders to call.
        //
        // Workaround for BCT/CCI not understanding that "GetReaders(SSOSecretParams)"
        // overrides "GetReaders(TParams)". ~ t-mattmc@microsoft.com 2016-07-11
        protected abstract PrincipalHandle[] GetReaders(object/*TParams*/ theParams);

        // TODO: In the real SVX API, currentPrincipal should be an ambient
        // variable of some kind (maybe not global if we want to run tests that
        // simulate multiple principals in the same process).
        [BCTOmitImplementation]
        public Secret Generate(TParams theParams, Principal currentPrincipal)
        {
            var readers = (PrincipalHandle[])GetReaders(theParams).Clone();
            if (!readers.Contains(currentPrincipal))
                throw new Exception("Secret generated by a principal not on its reader list: " +
                    "something is very wrong.");
            return new Secret {
                secretValue = RawGenerate(theParams),
                knownReaders = readers
            };
        }

        [BCTOmitImplementation]
        void RawVerify(TParams theParams, Secret secret)
        {
            RawVerify(theParams, secret.secretValue);
        }

        // I guess if you really want to try a Verify that might fail and catch
        // the exception, then the AssumeValidSecret won't happen in that case.
        public void Verify(TParams theParams, Secret secret)
        {
            try
            {
                RawVerify(theParams, secret);
            }
            // Be sure that BCT checks for an exception here since this is
            // security-critical.  (I'm not sure how robust its exception
            // modeling is in general.)
            catch { throw; }
            // I'm not sure this is necessary; hopefully it won't hurt.
            VProgram_API.Assert(secret.secretValue != null);
            VProgram_API.AssumeValidSecret(secret.secretValue, GetReaders(theParams));
        }
    }

}
