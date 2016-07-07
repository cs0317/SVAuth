using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Reflection;
using Newtonsoft.Json;
using Utils = SVX.Utils;

namespace SVX2
{
    public static class SVX_Ops
    {
        private static SymT GatherSymTs(SVX_MSG msg)
        {
            // TODO: traverse nested
            var rootSymT = (SymT)msg.symT;
            return (rootSymT == null) ? new SymTNondet { typeFullName = msg.GetType().FullName } : rootSymT;
        }
        private static T FillSymT<T>(T msg, SymT symT) where T : SVX_MSG
        {
            msg.symT = symT;
            return msg;
        }

        private static SymT MakeSymTForMethodCall(Delegate del, SymT[] inputSymTs)
        {
            Participant participant = del.Target as Participant;
            if (participant == null)
                throw new ArgumentException("Delegate must belong to an SVX participant object");
            MethodInfo mi = del.GetMethodInfo();
            return new SymTMethod {
                principal = participant.SVXPrincipal,
                runtimeTypeFullName = participant.GetType().FullName,
                // XXX Verify that method is unique and doesn't use generics?
                methodName = mi.Name,
                methodReturnTypeFullName = mi.ReturnType.FullName,
                methodArgTypeFullNames = (from p in mi.GetParameters() select p.ParameterType.FullName).ToArray(),
                inputSymTs = inputSymTs,
            };
        }
        public static T Call<T1, T>(Func<T1, T> f, T1 input)
            where T : SVX_MSG where T1 : SVX_MSG
        {
            return FillSymT(f(input), MakeSymTForMethodCall(f, new SymT[] { GatherSymTs(input) }));
        }
        public static T Call<T1, T2, T>(Func<T1, T2, T> f, T1 input1, T2 input2)
            where T : SVX_MSG where T1 : SVX_MSG where T2 : SVX_MSG
        {
            return FillSymT(f(input1, input2), MakeSymTForMethodCall(f, new SymT[] { GatherSymTs(input1), GatherSymTs(input2) }));
        }
        public static void Certify<T>(T msg, Func<T, bool> predicate, Principal[] trustedParties) where T : SVX_MSG
        {
            if (predicate.Target != null)
                // For now.  As long as we allow participants on SVX method
                // calls, it wouldn't be bad to allow them here too.
                throw new ArgumentException("Predicate must be a static method");

            MethodInfo mi = predicate.GetMethodInfo();
            var c = new CertificationRequest {
                scrutineeSymT = GatherSymTs(msg),
                methodName = mi.Name,
                methodDeclaringTypeFullName = mi.DeclaringType.FullName,
                methodArgTypeFullName = mi.GetParameters()[0].ParameterType.FullName,
                // XXX Establish a style guide for passing lists around.
                trustedParties = trustedParties.ToArray()
            };

            // TODO: Cache based on c.  Means we need to implement Equals/GetHashCode.
            if (!LocalCertifier.Certify(c))
                // TODO: Custom exception type
                throw new Exception("SVX certification failed.");
        }

        // For testing purposes until we have real export/import to use in an example.
        public static void Transfer(SVX_MSG msg, PrincipalHandle producer, PrincipalHandle sender)
        {
            if (producer == null || sender == null)
                // Auto-generate them instead?  But we'd need to know the issuer.
                // We may eventually have a global variable for the current party.
                throw new ArgumentNullException();
            msg.producer = producer;
            msg.sender = sender;
            msg.symT = new SymTTransfer {
                originalSymT = (SymT)msg.symT,
                // Only Principals are recorded concretely.
                producer = producer as Principal,
                sender = sender as Principal
            };
        }
    }

#if false
    public class Secret
    {
        string value;
        PrincipalHandle[] readers;
    }

    public class SecretGenerator
    {

    }
    public class MessageFormat
    {

    }
#endif

}
