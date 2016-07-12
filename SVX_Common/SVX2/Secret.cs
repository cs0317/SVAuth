using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SVX2
{
    public class Secret
    {
        internal string secretValue;
        internal PrincipalHandle[] knownReaders;
    }

    /* A SecretGenerator should have the property that, for the purposes of our
     * model, there is no way to come up with a secretValue that passes Verify
     * for particular parameters except to get it from Generate.  Examples:
     * signatures or HMACs.  For signatures, if you have only the public key,
     * you can define a SecretGenerator where RawGenerate throws an
     * InvalidOperationException. */
    // Workaround for BCT/CCI not understanding that "Generate(SSOSecretParams)"
    // overrides "Generate(TParams)". ~ t-mattmc@microsoft.com 2016-07-11
    public abstract class SecretGenerator/*<TParams>*/
    {
        protected abstract string RawGenerate(object/*TParams*/ theParams);
        protected abstract bool RawVerify(object/*TParams*/ theParams, string secretValue);

        // NOTE: We need to pay attention to make sure that enough information
        // is recorded for a symbolic proof about the readers to go through.  At
        // minimum, that probably means the exact dynamic type of the
        // SecretGenerator so we know which override of GetReaders to call.
        protected abstract PrincipalHandle[] GetReaders(object/*TParams*/ theParams);

        [BCTOmitImplementation]
        public Secret Generate(object/*TParams*/ theParams)
        {
            return new Secret {
                secretValue = RawGenerate(theParams),
                knownReaders = (PrincipalHandle[])GetReaders(theParams).Clone()
            };
        }

        [BCTOmitImplementation]
        bool RawVerify(object/*TParams*/ theParams, Secret secret)
        {
            return RawVerify(theParams, secret.secretValue);
        }

        public bool Verify(object/*TParams*/ theParams, Secret secret)
        {
            bool result = RawVerify(theParams, secret);
            if (result)
            {
                VProgram_API.AssumeValidSecret(secret.secretValue, GetReaders(theParams));
            }
            return result;
        }
    }
}
