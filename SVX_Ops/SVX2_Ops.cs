using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Reflection;
using Newtonsoft.Json;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics.Contracts;

namespace SVX2
{
    public static class SVX_Ops
    {
        private static SymT MakeSymTForMethodCall(Delegate del, SymT[] inputSymTs)
        {
            Participant participant = del.Target as Participant;
            if (participant == null)
                throw new ArgumentException("Delegate must belong to an SVX participant object");
            var m = new SymTMethod();
            m.participantId = participant.SVXParticipantId;
            m.runtimeTypeFullName = participant.GetType().FullName;
            MethodInfo mi = del.GetMethodInfo();
            // XXX Verify that method is unique and doesn't use generics?
            m.methodName = mi.Name;
            m.methodReturnTypeFullName = mi.ReturnType.FullName;
            m.methodArgTypeFullNames = (from p in mi.GetParameters() select p.ParameterType.FullName).ToArray();
            m.inputSymTs = inputSymTs;
            return m;
        }
        public static SVX_MSG<T> Call<T1, T>(Func<T1, T> f, SVX_MSG<T1> input)
        {
            return new SVX_MSG<T>(f(input.Get()), MakeSymTForMethodCall(f, new SymT[] { input.SymT }));
        }
        public static SVX_MSG<T> Call<T1, T2, T>(Func<T1, T2, T> f, SVX_MSG<T1> input1, SVX_MSG<T2> input2)
        {
            return new SVX_MSG<T>(f(input1.Get(), input2.Get()), MakeSymTForMethodCall(f, new SymT[] { input1.SymT, input2.SymT }));
        }
        public static void Certify<T>(SVX_MSG<T> msg, Func<T, bool> predicate)
        {
            if (predicate.Target != null)
                throw new ArgumentException("Predicate must be a static method");  // for now
            MethodInfo mi = predicate.GetMethodInfo();
            var c = new Certification();
            c.scrutineeSymT = msg.SymT;
            c.methodName = mi.Name;
            c.methodDeclaringTypeFullName = mi.DeclaringType.FullName;
            c.methodArgTypeFullName = mi.GetParameters()[0].ParameterType.FullName;

            // TODO: Cache based on c.  Means we need to implement Equals/GetHashCode.
            if (!LocalVerifier.GenerateAndVerify(c))
                // TODO: Custom exception type
                throw new Exception("SVX certification failed.");
        }
    }
    public interface Participant
    {
        string SVXParticipantId { get; }
    }
    class Certification
    {
        internal SymT scrutineeSymT;
        internal string methodDeclaringTypeFullName;
        internal string methodName;
        internal string methodArgTypeFullName;
    }
    abstract class SymT
    {
        // TODO
    }
    class SymTNondet : SymT
    {
        internal string typeFullName;
        internal SymTNondet(string typeFullName)
        {
            this.typeFullName = typeFullName;
        }
    }
    class SymTMethod : SymT
    {
        // This can probably be a real Principal.
        internal string participantId;
        internal string runtimeTypeFullName;
        internal string methodName;
        internal string methodReturnTypeFullName;
        internal string[] methodArgTypeFullNames;
        internal SymT[] inputSymTs;
    }
#if false
    class SymTSays : SymT
    {

    }
#endif
#if false
    public class PrincipalFacet
    {

    }
    public class Secret
    {
        string value;
        PrincipalFacet[] readers;
    }
#endif
    public sealed class SVX_MSG<T>
    {
        JObject payload;
        internal SymT SymT;

        // TODO: We may give this a name.
        public SVX_MSG(T payload) : this(payload, new SymTNondet(typeof(T).FullName)) { }
        internal SVX_MSG(T payload, SymT SymT)
        {
            // Copied from ReflectObject.  Will need to be fancier.
            var writer = new JTokenWriter();
            new JsonSerializer().Serialize(writer, payload);
            this.payload = (JObject)writer.Token;
            this.SymT = SymT;
        }

        public T Get()
        {
            // Copied from UnreflectObject.
            return new JsonSerializer().Deserialize<T>(new JTokenReader(payload));
        }
    }
#if false
    public class SecretGenerator
    {

    }
    public class MessageFormat
    {

    }
#endif

    class VProgramGenerator
    {
        StringBuilder sb = new StringBuilder();
        int nextVarNumber = 0;
        string nextVar()
        {
            return "x" + (nextVarNumber++);
        }
        private static string QuoteParticipantId(string x)
        {
            // TODO: Figure out the right way to make a C# string literal.
            Contract.Assume(Regex.IsMatch(x, "^[_A-Za-z0-9]*$"));
            return "\"" + x + "\"";
        }
        string Visit(SymT symT)
        {
            // XXX: Currently we cannot deal with non-public participant classes
            // and methods.  It's an open question if we should be able to and
            // how it should be implemented.

            SymTNondet symTNondet;
            SymTMethod symTMethod;
            string outputVarName;
            if ((symTNondet = symT as SymTNondet) != null)
            {
                outputVarName = nextVar();
                sb.AppendFormat("{0} {1} = SVX2.VProgram_API.Nondet<{0}>();\n", symTNondet.typeFullName, outputVarName);
            }
            else if ((symTMethod = symT as SymTMethod) != null)
            {
                // This has side effects, so evaluate it right away.
                string[] argVarNames = (from i in symTMethod.inputSymTs select Visit(i)).ToArray();
                outputVarName = nextVar();
                sb.AppendFormat("{0} {1} = SVX2.VProgram_API.GetParticipant<{2}>({3}).{4}({5});\n",
                    symTMethod.methodReturnTypeFullName, outputVarName,
                    symTMethod.runtimeTypeFullName, QuoteParticipantId(symTMethod.participantId), symTMethod.methodName,
                    string.Join(", ", argVarNames));
            }
            else
            {
                throw new Exception("Unexpected SymT");
            }
            return outputVarName;
        }
        internal VProgramGenerator(Certification certification)
        {
            sb.Append("public static class Program {\n");
            sb.Append("public static void Main() {\n");
            string scrutineeVarName = Visit(certification.scrutineeSymT);
            // We list System.Diagnostics.Contracts as a direct dependency as a
            // good practice, even though we'll nearly always get it as an
            // indirect dependency.
            sb.AppendFormat("System.Diagnostics.Contracts.Contract.Assert({0}.{1}({2}));\n",
                certification.methodDeclaringTypeFullName, certification.methodName, scrutineeVarName);
            sb.Append("}\n");
            sb.Append("}\n");
        }
        internal string GetSynthesizedPortion()
        {
            return sb.ToString();
        }
    }

}
