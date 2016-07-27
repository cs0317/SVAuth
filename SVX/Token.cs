using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace SVX
{
    // /All/ tokens uniquely identify the original parameters.
    //
    // Optional properties of tokens (can be combined):
    // - Authenticates the bearer: "Secret"
    // - Authenticates an SVX_MSG: "Message"
    //   - Future: Authenticates a custom predicate: term TBD
    // - Embeds the original parameters: "Payload"
    //
    // (We are just adding support for the combinations we need in actual
    // protocols.  It's hard to know if we got everything.)

    /* A TokenGenerator (any variant) should have the property that, for the purposes of our
     * model, there is no way to come up with a secretValue that passes Verify
     * for particular parameters except to get it from Generate.  Examples:
     * signatures or HMACs.  For signatures, if you have only the public key,
     * you can define a TokenGenerator where RawGenerate throws an
     * InvalidOperationException. */

    public abstract class TokenGenerator<TParams>
    {
        protected abstract string RawGenerate(TParams theParams);

        // On verification failure, this should throw an exception.  This makes
        // it easy to provide info about the nature of the failure rather than
        // just a boolean.  (The alternative would be to return a boolean and
        // log the info somewhere else.)
        protected abstract void RawVerify(TParams theParams, string tokenValue);

        [BCTOmitImplementation]
        string RawGenerateWrapper(TParams theParams)
        {
            return RawGenerate(theParams);
        }

        public string Generate(TParams theParams)
        {
            var tokenValue = RawGenerateWrapper(theParams);
            VProgram_API.AssumeValidToken(tokenValue, theParams);
            return tokenValue;
        }

        [BCTOmitImplementation]
        void RawVerifyWrapper(TParams theParams, string tokenValue)
        {
            RawVerify(theParams, tokenValue);
        }

        // I guess if you really want to try a Verify that might fail and catch
        // the exception, then the AssumeValidToken won't happen in that case.
        public void Verify(TParams theParams, string tokenValue)
        {
            RawVerifyWrapper(theParams, tokenValue);
            // I'm not sure this is necessary; hopefully it won't hurt.
            VProgram_API.Assert(tokenValue != null);
            VProgram_API.AssumeValidToken(tokenValue, theParams);
        }
    }

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

        public override bool Equals(object obj)
        {
            var obj2 = obj as Secret;
            return obj2 != null && obj2.secretValue == secretValue;
        }

        public override int GetHashCode()
        {
            // This is not cryptographically secure, but we're only trying to
            // make it hard, not impossible, for developers to do something bad.
            return secretValue.GetHashCode();
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

    public abstract class SecretGenerator<TParams>
    {
        protected abstract string RawGenerate(TParams theParams);

        // On verification failure, this should throw an exception.  This makes
        // it easy to provide info about the nature of the failure rather than
        // just a boolean.  (The alternative would be to return a boolean and
        // log the info somewhere else.)
        protected abstract void RawVerify(TParams theParams, string secretValue);

        // Should return a new array each time.
        //
        // NOTE: We need to pay attention to make sure that enough information
        // is recorded for a symbolic proof about the readers to go through.  At
        // minimum, that probably means the exact dynamic type of the
        // SecretGenerator so we know which override of GetReaders to call.
        //
        // Workaround for BCT/CCI not understanding that "GetReaders(SSOSecretParams)"
        // overrides "GetReaders(TParams)". ~ t-mattmc@microsoft.com 2016-07-11
        protected abstract PrincipalHandle[] GetReaders(object/*TParams*/ theParams);

        [BCTOmitImplementation]
        string RawGenerateWrapper(TParams theParams)
        {
            return RawGenerate(theParams);
        }

        // TODO: In the real SVX API, currentPrincipal should be an ambient
        // variable of some kind (maybe not global if we want to run tests that
        // simulate multiple principals in the same process).
        public Secret Generate(TParams theParams, Principal currentPrincipal)
        {
            var readers = GetReaders(theParams);
            if (!VProgram_API.InVProgram)
            {
                if (!readers.Contains(currentPrincipal))
                    throw new Exception("Misconfiguration: secret generated by a principal not on its reader list.");
            }
            var secretValue = RawGenerateWrapper(theParams);
            VProgram_API.AssumeValidSecret(secretValue, theParams, readers);
            return new Secret {
                secretValue = secretValue,
                knownReaders = readers
            };
        }

        [BCTOmitImplementation]
        void RawVerifyWrapper(TParams theParams, Secret secret)
        {
            RawVerify(theParams, secret.secretValue);
        }

        // I guess if you really want to try a Verify that might fail and catch
        // the exception, then the AssumeValidSecret won't happen in that case.
        public void Verify(TParams theParams, Secret secret)
        {
            RawVerifyWrapper(theParams, secret);
            // I'm not sure this is necessary; hopefully it won't hurt.
            VProgram_API.Assert(secret.secretValue != null);
            VProgram_API.AssumeValidSecret(secret.secretValue, theParams, GetReaders(theParams));
        }
    }

    public abstract class MessagePayloadSecretGenerator<TMessage> where TMessage : SVX_MSG
    {
        protected internal abstract PrincipalHandle Signer { get; }

        protected abstract string RawGenerate(TMessage message);
        protected abstract TMessage RawExtractUnverified(string secretValue);

        // On verification failure, this should throw an exception.
        protected abstract TMessage RawVerifyAndExtract(string secretValue);

        // Should return a new array each time.
        protected internal abstract PrincipalHandle[] GetReaders(object/*TMessage*/ message);

        [BCTOmitImplementation]
        string RawGenerateWrapper(TMessage message)
        {
            return RawGenerate(message);
        }

        [BCTOmitImplementation]
        TMessage RawExtractUnverifiedWrapper(string secretValue)
        {
            return RawExtractUnverified(secretValue);
        }

        [BCTOmitImplementation]
        TMessage RawVerifyAndExtractWrapper(string secretValue)
        {
            return RawVerifyAndExtract(secretValue);
        }

        public PayloadSecret<TMessage> Generate(TMessage message, Principal currentPrincipal)
        {
            var readers = GetReaders(message);
            // None of these checks are really the business of the vProgram, and
            // in particular, !message.active will be a contradiction.
            if (!VProgram_API.InVProgram)
            {
                if (currentPrincipal != Signer)
                    throw new Exception("Misconfiguration: current principal is signing a message " +
                        "but is not the designated signer for this secret generator.");
                // XXX Would it be more consistent to make the message nondet instead?
                if (!message.active)
                    throw new InvalidOperationException("Cannot sign a message without an active SymT");
                if (!readers.Contains(currentPrincipal))
                    throw new Exception("Misconfiguration: secret generated by a principal not on its reader list.");
            }
            var secretValue = RawGenerateWrapper(message);
            VProgram_API.AssumeValidSecret(secretValue, message, readers);
            return new PayloadSecret<TMessage>
            {
                theParams = message,
                secretValue = secretValue,
                knownReaders = readers
            };
        }

        // To prevent a secret value from being leaked by passing it to a
        // PayloadSecretGenerator for the wrong secret format, which thinks the
        // secret part is a public part and extracts it, these methods are
        // restricted to be called only via a MessageStructure on import.  TBD
        // what to do if this doesn't end up meeting our needs.

        internal void ExtractUnverified(PayloadSecret<TMessage> secret)
        {
            secret.theParams = RawExtractUnverified(secret.secretValue);
            VProgram_API.Assert(secret.theParams != null);
        }

        internal void VerifyAndExtract(PayloadSecret<TMessage> secret)
        {
            secret.theParams = RawVerifyAndExtract(secret.secretValue);
            // This currently can't be called from SVX methods, so we don't
            // actually have to do the vProgram-specific stuff.
            //// Maybe non-nullness of the root message is as much as we can say in general?
            //VProgram_API.Assert(secret.theParams != null);
            //VProgram_API.Assert(secret.secretValue != null);
            //VProgram_API.AssumeValidSecret(secret.secretValue, GetReaders(secret.theParams));
            // Verification succeeded, so we should be able to activate the SymT.
            SVX_Ops.TransferNested(secret.theParams, Signer);
        }
    }

}
