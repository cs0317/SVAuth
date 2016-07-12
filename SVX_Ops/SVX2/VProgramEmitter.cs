using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SVX2
{
    class VProgramEmitter
    {
        StringBuilder sb = new StringBuilder();
        int nextVarNumber = 0;
        string nextVar(string prefix)
        {
            return prefix + (nextVarNumber++);
        }
        private static string Quote(string x)
        {
            // TODO: Figure out the right way to make a C# string literal.
            Contract.Assume(Regex.IsMatch(x, "^[_A-Za-z0-9]*$"));
            return "\"" + x + "\"";
        }
        string EmitPrincipal(Principal p) => "SVX2.Principal.Of(" + Quote(p.name) + ")";
        string EmitPrincipalOrNondet(Principal p)
            => (p == null) ? "SVX2.VProgram_API.Nondet<SVX2.Principal>()" : EmitPrincipal(p);

        // Nested types... Should we use a wrapper class in SymTs (that is
        // still serializable, unlike System.Type) and move this method there?
        string FormatTypeFullName(string fullName) => fullName.Replace('+', '.');

        HashSet<ParticipantId> participantsSeen = new HashSet<ParticipantId>();
        void ScanParticipants(SymT symT)
        {
            var symTMethod = symT as SymTMethod;
            if (symTMethod != null)
                participantsSeen.Add(symTMethod.participantId);
            foreach (var embedded in symT.EmbeddedSymTs)
                ScanParticipants(embedded);
        }

        string EmitMessage(SymT symT)
        {
            // XXX: Currently we cannot deal with non-public participant classes
            // and methods.  It's an open question if we should be able to and
            // how it should be implemented.  I guess one way is for developers
            // to write [InternalsVisibleTo("VProgram")].

            SymTNondet symTNondet;
            SymTMethod symTMethod;
            //SymTComposite symTComposite;
            SymTTransfer symTTransfer;
            string outputVarName;

            // Consider using a visitor.  It's not worth it yet. :/
            if ((symTNondet = symT as SymTNondet) != null)
            {
                outputVarName = nextVar("msg");
                sb.AppendFormat("{0} {1} = SVX2.VProgram_API.Nondet<{0}>();\n",
                    FormatTypeFullName(symTNondet.messageTypeFullName), outputVarName);
            }
            else if ((symTMethod = symT as SymTMethod) != null)
            {
                // This has side effects, so evaluate it right away.
                string[] argVarNames = (from i in symTMethod.inputSymTs select EmitMessage(i)).ToArray();
                outputVarName = nextVar("msg");
                sb.AppendFormat("{0} {1} = SVX2.VProgram_API.GetParticipant<{2}>(SVX2.Principal.Of({3})).{4}({5});\n",
                    FormatTypeFullName(symTMethod.methodReturnTypeFullName), outputVarName,
                    FormatTypeFullName(symTMethod.participantId.typeFullName),
                    Quote(symTMethod.participantId.principal.name), symTMethod.methodName,
                    string.Join(", ", argVarNames));
            }
            // This needs a rewrite to avoid depending on Equals.
#if false
            else if ((symTComposite = symT as SymTComposite) != null)
            {
                string rootVarName = Visit(symTComposite.rootSymT);
                foreach (var entry in symTComposite.nestedSymTs)
                {
                    string nestedVarName = Visit(entry.symT);
                    sb.AppendFormat("System.Diagnostics.Contracts.Contract.Assume({0}.{1}.Equals({2}));\n",
                        rootVarName, entry.fieldPath, nestedVarName);
                }
                outputVarName = rootVarName;
            }
#endif
            else if ((symTTransfer = symT as SymTTransfer) != null)
            {
                string producerVarName = nextVar("producer");
                sb.AppendFormat("SVX2.PrincipalHandle {0} = {1};\n", producerVarName, EmitPrincipalOrNondet(symTTransfer.producer));
                outputVarName = nextVar("msg");
                sb.AppendFormat("{0} {1};\n", FormatTypeFullName(symTTransfer.MessageTypeFullName), outputVarName);
                sb.AppendFormat("if (SVX2.VProgram_API.ActsForAny({0}, trustedParties)) {{\n", producerVarName);
                {
                    string inputVarName = EmitMessage(symTTransfer.originalSymT);
                    sb.AppendFormat("{0} = {1};\n", outputVarName, inputVarName);
                }
                sb.AppendFormat("}} else {0} = SVX2.VProgram_API.Nondet<{1}>();\n",
                    outputVarName, FormatTypeFullName(symTTransfer.MessageTypeFullName));
                sb.AppendFormat("{0}.producer = {1};\n", outputVarName, producerVarName);
                sb.AppendFormat("{0}.sender = {1};\n", outputVarName, EmitPrincipalOrNondet(symTTransfer.sender));

                /* Currently, we assume all concrete message types are in the
                 * SVAuth assembly.  To lift that restriction, we'd have to
                 * either include the assembly qualified name in the SymT or
                 * just look for the type in all uploaded assemblies.  Once we
                 * can have N parties with assemblies named "SVAuth" with
                 * different code or even different definitions of the
                 * transferred message types (!), we'll need to add the hash of
                 * the assembly and we'll need to copy messages one field at a
                 * time between the differently defined types. */
                Type messageType = Type.GetType(symTTransfer.MessageTypeFullName + ", SVAuth");
                foreach (var acc in FieldFinder<Secret>.FindFields(messageType))
                {
                    sb.AppendFormat("SVX2.VProgram_API.AssumeBorne({0}.producer, {0}.{1}.secretValue);\n", outputVarName, acc.name);
                    sb.AppendFormat("SVX2.VProgram_API.AssumeBorne({0}.sender, {0}.{1}.secretValue);\n", outputVarName, acc.name);
                }
            }
            else
            {
                throw new NotImplementedException("Unhandled SymT");
            }
            return outputVarName;
        }

        internal VProgramEmitter(CertificationRequest certReq)
        {
            sb.Append("public static class Program {\n");
            sb.Append("public static void Main() {\n");
            sb.Append("SVX2.VProgram_API.InVProgram = true;\n");

            // BCT WORKAROUND: new T[] { ... } (yes, in emitted code!)
            // Yes, the array is covariant to be passed to ActsForAny.
            sb.AppendFormat("SVX2.Principal[] trustedParties = new SVX2.Principal[{0}];\n", certReq.trustedParties.Length);
            for (int i = 0; i < certReq.trustedParties.Length; i++)
                sb.AppendFormat("trustedParties[{0}] = {1};\n", i, EmitPrincipalOrNondet(certReq.trustedParties[i]));

            participantsSeen.UnionWith(certReq.predicateParticipants);
            ScanParticipants(certReq.scrutineeSymT);
            foreach (var participant in participantsSeen)
                sb.AppendFormat("SVX2.VProgram_API.CreateParticipant({0}, new {1}());\n",
                    EmitPrincipal(participant.principal), FormatTypeFullName(participant.typeFullName));

            string scrutineeVarName = EmitMessage(certReq.scrutineeSymT);
            // We list System.Diagnostics.Contracts as a direct dependency as a
            // good practice, even though we'll nearly always get it as an
            // indirect dependency.
            sb.AppendFormat("System.Diagnostics.Contracts.Contract.Assert({0}.{1}({2}));\n",
                FormatTypeFullName(certReq.methodDeclaringTypeFullName), certReq.methodName, scrutineeVarName);
            sb.Append("}\n");
            sb.Append("}\n");
        }

        internal string GetSynthesizedPortion()
        {
            return sb.ToString();
        }
    }
}
