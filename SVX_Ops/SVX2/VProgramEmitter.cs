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
        int indent = 0;
        void AppendFormattedLine(string format, params object[] args)
        {
            sb.Append(new string(' ', indent));
            sb.AppendFormat(format, args);
            sb.AppendLine();
        }
        void IncreaseIndent()
        {
            indent += 4;
        }
        void DecreaseIndent()
        {
            indent -= 4;
        }

        int nextVarNumber = 0;
        string nextVar(string prefix)
        {
            return prefix + (nextVarNumber++);
        }

        // Utilities
        static string Quote(string x)
        {
            // TODO: Figure out the right way to make a C# string literal.
            Contract.Assume(Regex.IsMatch(x, "^[_A-Za-z0-9]*$"));
            return "\"" + x + "\"";
        }
        static string EmitPrincipal(Principal p) => "SVX2.Principal.Of(" + Quote(p.name) + ")";
        static string EmitPrincipalOrNondet(Principal p)
            => (p == null) ? "SVX2.VProgram_API.Nondet<SVX2.Principal>()" : EmitPrincipal(p);

        // This method is designed to meet our current needs, where messageVar
        // is assumed to always be nonnull.
        static string MakeFieldPathNullConditional(string messageVar, string fieldPath)
        {
            // The ?. operator seems to crash the CCI unstacker.
            //return messageVar + "." + fieldPath.Replace(".", "?.");

            var pos = fieldPath.IndexOf('.');
            if (pos == -1)
                return messageVar + "." + fieldPath;
            var sb = new StringBuilder("((");
            bool first = true;
            do
            {
                if (!first) sb.Append(" || ");
                sb.AppendFormat("{0}.{1} == null", messageVar, fieldPath.Substring(0, pos));
            } while ((pos = fieldPath.IndexOf('.', pos + 1)) != -1);

            sb.AppendFormat(") ? null : {0}.{1})", messageVar, fieldPath);
            return sb.ToString();
        }

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
            SymTComposite symTComposite;
            SymTTransfer symTTransfer;
            string outputVarName;

            // Consider using a visitor.  It's not worth it yet. :/
            if ((symTNondet = symT as SymTNondet) != null)
            {
                outputVarName = nextVar("msg");
                // FIXME: Nondetting arbitrary data structures will cause
                // aliasing nightmares.  We need to emit a specialized Nondet
                // for each message type.
                AppendFormattedLine("{0} {1} = SVX2.VProgram_API.Nondet<{0}>();",
                    FormatTypeFullName(symTNondet.messageTypeFullName), outputVarName);
            }
            else if ((symTMethod = symT as SymTMethod) != null)
            {
                // This has side effects, so evaluate it right away.
                string[] argVarNames = (from i in symTMethod.inputSymTs select EmitMessage(i)).ToArray();
                outputVarName = nextVar("msg");
                AppendFormattedLine("{0} {1} = SVX2.VProgram_API.GetParticipant<{2}>(SVX2.Principal.Of({3})).{4}({5});",
                    FormatTypeFullName(symTMethod.methodReturnTypeFullName), outputVarName,
                    FormatTypeFullName(symTMethod.participantId.typeFullName),
                    Quote(symTMethod.participantId.principal.name), symTMethod.methodName,
                    string.Join(", ", argVarNames));
            }
            // This needs a rewrite to avoid depending on Equals.
            else if ((symTComposite = symT as SymTComposite) != null)
            {
                SymTTransfer rootTransfer;
                if (symTComposite.rootSymT is SymTNondet)
                {
                    // Nondet the root message and then overwrite the nested
                    // messages that we have information about.
                    outputVarName = EmitMessage(symTComposite.rootSymT);
                    foreach (var entry in symTComposite.nestedSymTs)
                    {
                        string nestedVarName = EmitMessage(entry.symT);
                        // This code is untested...
                        for (int pos = 0; (pos = entry.fieldPath.IndexOf('.', pos)) != -1; pos++)
                        {
                            AppendFormattedLine("System.Diagnostics.Contracts.Contract.Assume({0}.{1} != null);",
                                outputVarName, entry.fieldPath.Substring(0, pos));
                        }
                        AppendFormattedLine("{0}.{1} = {2};",
                            outputVarName, entry.fieldPath, nestedVarName);
                    }
                }
                else if(symTComposite.rootSymT is SymTMethod)
                {
                    // In this case, we assume the information in the rootSymT
                    // subsumes the information in the nested SymTs and emit
                    // code only for the rootSymT.  If we had Equals for
                    // messages, we could assume the nested messages equal, but
                    // this is extra work which I don't believe is needed for
                    // our examples so far.
                    outputVarName = EmitMessage(symTComposite.rootSymT);
                }
                else if ((rootTransfer = symTComposite.rootSymT as SymTTransfer) != null)
                {
                    // The emitted code for the SymTTransfer will determine
                    // whether the transfer is trusted.  If so, just use the
                    // transfer and ignore the nested messages, as in the
                    // SymTMethod case.  If not, it will use the fallback we
                    // specify.
                    outputVarName = EmitMessage(new SymTTransfer(rootTransfer) {
                        fallback = new SymTComposite
                        {
                            rootSymT = new SymTNondet { messageTypeFullName = symTComposite.MessageTypeFullName },
                            nestedSymTs = symTComposite.nestedSymTs
                        }
                    });
                }
                else
                {
                    // We should never have double composites.
                    throw new NotImplementedException("Unhandled root SymT in composite");
                }
            }
            else if ((symTTransfer = symT as SymTTransfer) != null)
            {
                string producerVarName = nextVar("producer");
                AppendFormattedLine("SVX2.PrincipalHandle {0} = {1};", producerVarName, EmitPrincipalOrNondet(symTTransfer.producer));
                outputVarName = nextVar("msg");
                AppendFormattedLine("{0} {1};", FormatTypeFullName(symTTransfer.MessageTypeFullName), outputVarName);
                AppendFormattedLine("if (SVX2.VProgram_API.ActsForAny({0}, trustedParties)) {{", producerVarName);
                {
                    IncreaseIndent();
                    string inputVarName = EmitMessage(symTTransfer.originalSymT);
                    AppendFormattedLine("{0} = {1};", outputVarName, inputVarName);
                    DecreaseIndent();
                }
                AppendFormattedLine("}} else {{");
                {
                    IncreaseIndent();
                    string inputVarName = EmitMessage(symTTransfer.fallback ??
                        new SymTNondet { messageTypeFullName = symTTransfer.MessageTypeFullName });
                    AppendFormattedLine("{0} = {1};", outputVarName, inputVarName);
                    DecreaseIndent();
                }
                AppendFormattedLine("}}");
                AppendFormattedLine("{0}.SVX_producer = {1};", outputVarName, producerVarName);
                AppendFormattedLine("{0}.SVX_sender = {1};", outputVarName, EmitPrincipalOrNondet(symTTransfer.sender));

                // If we verified secrets on import, they are valid regardless
                // of whether the transfer was trusted.
                foreach (var entry in symTTransfer.payloadSecretsVerifiedOnImport)
                {
                    // I'm unsure of BCT handling of null dereferences in
                    // general, but here we can definitely assume non-null.
                    AppendFormattedLine("System.Diagnostics.Contracts.Contract.Assume({0} != null);",
                        MakeFieldPathNullConditional(outputVarName, entry.fieldPath));
                    // Follow the commented-out lines in
                    // MessagePayloadSecretGenerator.VerifyAndExtract.  I'd like
                    // to define a helper method for this, but until I merge
                    // SVX_Common and SVX_Ops, I'm between a rock and a hard
                    // place because the method needs to be BCT translated but
                    // needs to reference MessagePayloadSecretGenerator.
                    AppendFormattedLine("System.Diagnostics.Contracts.Contract.Assume({0}.{1}.secretValue != null);",
                        outputVarName, entry.fieldPath);
                    AppendFormattedLine("System.Diagnostics.Contracts.Contract.Assume({0}.{1}.theParams != null);",
                        outputVarName, entry.fieldPath);
                    // XXX We're assuming the generator has a no-arg public
                    // constructor and doesn't need any configuration parameters.
                    AppendFormattedLine("SVX2.VProgram_API.AssumeValidSecret({0}.{1}.secretValue, " +
                        "new {2}().GetReaders({0}.{1}.theParams));",
                        outputVarName, entry.fieldPath, FormatTypeFullName(entry.secretGeneratorTypeFullName));
                }

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
                    AppendFormattedLine("SVX2.VProgram_API.AssumeBorne({0}.SVX_producer, {1});",
                        outputVarName, MakeFieldPathNullConditional(outputVarName, acc.path + ".secretValue"));
                    AppendFormattedLine("SVX2.VProgram_API.AssumeBorne({0}.SVX_sender, {1});",
                        outputVarName, MakeFieldPathNullConditional(outputVarName, acc.path + ".secretValue"));
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
            AppendFormattedLine("public static class Program {{");
            IncreaseIndent();
            AppendFormattedLine("public static void Main() {{");
            IncreaseIndent();

            AppendFormattedLine("SVX2.VProgram_API.InVProgram = true;");

            sb.AppendLine();

            // BCT WORKAROUND: new T[] { ... } (yes, in emitted code!)
            // Yes, the array is covariant to be passed to ActsForAny.
            AppendFormattedLine("SVX2.Principal[] trustedParties = new SVX2.Principal[{0}];", certReq.trustedParties.Length);
            for (int i = 0; i < certReq.trustedParties.Length; i++)
                AppendFormattedLine("trustedParties[{0}] = {1};", i, EmitPrincipalOrNondet(certReq.trustedParties[i]));

            sb.AppendLine();

            participantsSeen.UnionWith(certReq.predicateParticipants);
            ScanParticipants(certReq.scrutineeSymT);
            foreach (var participant in participantsSeen)
                AppendFormattedLine("SVX2.VProgram_API.CreateParticipant({0}, new {1}());",
                    EmitPrincipal(participant.principal), FormatTypeFullName(participant.typeFullName));

            sb.AppendLine();

            string scrutineeVarName = EmitMessage(certReq.scrutineeSymT);

            sb.AppendLine();

            // We list System.Diagnostics.Contracts as a direct dependency as a
            // good practice, even though we'll nearly always get it as an
            // indirect dependency.
            AppendFormattedLine("System.Diagnostics.Contracts.Contract.Assert({0}.{1}({2}));",
                FormatTypeFullName(certReq.methodDeclaringTypeFullName), certReq.methodName, scrutineeVarName);

            DecreaseIndent();
            AppendFormattedLine("}}");
            DecreaseIndent();
            AppendFormattedLine("}}");
        }

        internal string GetSynthesizedPortion()
        {
            return sb.ToString();
        }
    }
}
