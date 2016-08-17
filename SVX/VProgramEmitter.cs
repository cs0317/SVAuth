using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SVX
{
    [BCTOmit]
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
            // Hope the C# compiler (and any tools we might use to view vPrograms) are fuzz-proof...
            return "@\"" + x.Replace("\"", "\"\"") + "\"";
        }
        static string EmitPrincipal(Principal p) =>
            "SVX.Principal.Of(" + Quote(p.name) + ")";
        static string EmitPrincipalHandle(PrincipalHandle ph)
        {
            Principal p;
            PrincipalFacet pf;
            if ((p = ph as Principal) != null)
            {
                return EmitPrincipal(p);
            }
            else if ((pf = ph as PrincipalFacet) != null)
            {
                // I don't think we use this, but might as well implement it.
                // ~ t-mattmc@microsoft.com 2016-07-19
                return "SVX.PrincipalFacet.Of(" + EmitPrincipalHandle(pf.issuer) + ", " + Quote(pf.id) + ")";
            }
            else
            {
                throw new NotImplementedException("Unexpected PrincipalHandle");
            }
        }
        static string EmitPrincipalHandleOrNondet(PrincipalHandle p)
            => (p == null) ? "SVX.VProgram_API.Nondet<SVX.PrincipalHandle>()" : EmitPrincipalHandle(p);

        static string EmitParticipant(SymTParticipantId id) =>
            string.Format("SVX.VProgram_API.GetParticipant<{0}>({1})",
                FormatTypeFullName(id.typeFullName), EmitPrincipalHandle(id.principal));

        // This method is designed to meet our current needs, where messageVar
        // is assumed to always be nonnull.
        string MakeFieldPathNullConditional(string messageVar, string fieldPath, string messageTypeFullName)
        {
            // The ?. operator seems to crash the CCI unstacker.
            //return messageVar + "." + fieldPath.Replace(".", "?.");

            var pos = fieldPath.IndexOf('.');
            if (pos == -1)
                return messageVar + "." + fieldPath;
            var condSB = new StringBuilder();
            bool first = true;
            do
            {
                if (!first) condSB.Append(" || ");
                first = false;
                condSB.AppendFormat("{0}.{1} == null", messageVar, fieldPath.Substring(0, pos));
            } while ((pos = fieldPath.IndexOf('.', pos + 1)) != -1);

            //return string.Format("(({0}) ? null : {1}.{2})", condSB.ToString(), messageVar, fieldPath);

            // Work around apparent bug in CCI unstacker where the "then" branch
            // of a complicated ?: assigns to stack_N_<correct_static_type> but
            // the result variable of the ?: is stack_N_System_Object.
            string type = FormatTypeFullName(
                GetTypeOfFieldPath(GetTypeByFullName(messageTypeFullName), fieldPath).FullName);

            string varName = nextVar("nullConditional");
            AppendFormattedLine("{0} {1};", type, varName);
            AppendFormattedLine("if ({0}) {{", condSB.ToString());
            {
                IncreaseIndent();
                AppendFormattedLine("{0} = null;", varName);
                DecreaseIndent();
            }
            AppendFormattedLine("}} else {{");
            {
                IncreaseIndent();
                AppendFormattedLine("{0} = {1}.{2};", varName, messageVar, fieldPath);
                DecreaseIndent();
            }
            AppendFormattedLine("}}");
            return varName;
        }

        // Nested types... Should we use a wrapper class in SymTs (that is
        // still serializable, unlike System.Type) and move this method there?
        static string FormatTypeFullName(string fullName) => fullName.Replace('+', '.');

        /* Currently, we assume all concrete message types are in the
         * SVAuth assembly.  To lift that restriction, we'd have to
         * either include the assembly qualified name in the SymT or
         * just look for the type in all uploaded assemblies.  Once we
         * can have N parties with assemblies named "SVAuth" with
         * different code or even different definitions of the
         * transferred message types (!), we'll need to add the hash of
         * the assembly and we'll need to copy messages one field at a
         * time between the differently defined types. */
        static Type GetTypeByFullName(string fullName) =>
            Type.GetType(fullName + ", SVAuth", true);

        static Type GetTypeOfFieldPath(Type type, string fieldPath)
        {
            string[] fieldNames = fieldPath.Split('.');
            foreach (var fieldName in fieldNames)
            {
                FieldInfo field = type.GetField(fieldName,
                    // NonPublic currently needed for Secret.secretValue.
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                type = field.FieldType;
            }
            return type;
        }

        HashSet<SymTParticipantId> participantsSeen = new HashSet<SymTParticipantId>();
        void ScanParticipants(SymT symT)
        {
            var symTMethod = symT as SymTMethod;
            if (symTMethod != null)
                participantsSeen.Add(symTMethod.participantId);
            foreach (var embedded in symT.EmbeddedSymTs)
                ScanParticipants(embedded);
        }

        class MessageReuseScope
        {
            internal Dictionary<string /* message id */, string /* emitted var name */> availableMessages
                = new Dictionary<string, string>();
            internal MessageReuseScope outer;
        }

        string EmitMessage(SymT symT, MessageReuseScope scope)
        {
            // First look in the scope.  This mechanism currently handles cases
            // where a later argument to a method call is derived from an
            // earlier one; that's enough for the authorization code flow example.
            string reuseVarName;
            for (var checkScope = scope; checkScope != null; checkScope = checkScope.outer)
                if (checkScope.availableMessages.TryGetValue(symT.messageId, out reuseVarName))
                    return reuseVarName;
            // Otherwise not found; proceed.

            // XXX: Currently we cannot deal with non-public participant classes
            // and methods.  It's an open question if we should be able to and
            // how it should be implemented.  I guess one way is for developers
            // to write [InternalsVisibleTo("VProgram")].  There shouldn't be
            // much risk of abuse because for the vProgram to access a program
            // element, someone authorized had to pass it to an SVX API.

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
                AppendFormattedLine("{0} {1} = SVX.VProgram_API.Nondet<{0}>();",
                    FormatTypeFullName(symTNondet.messageTypeFullName), outputVarName);
            }
            else if ((symTMethod = symT as SymTMethod) != null)
            {
                var newScope = new MessageReuseScope { outer = scope };
                var argVarNames = new List<string>();
                for (int i = 0; i < symTMethod.methodArgTypeFullNames.Length; i++)
                {
                    SymT inputSymT = symTMethod.inputSymTs[i];
                    string inputVarName;
                    if (inputSymT != null)
                    {
                        inputVarName = EmitMessage(inputSymT, newScope);
                        newScope.availableMessages[inputSymT.messageId] = inputVarName;
                    }
                    else
                    {
                        // Nondet non-message argument.  One could argue for using a SymTNondet
                        // even for non-message types.
                        inputVarName = nextVar("arg");
                        AppendFormattedLine("{0} {1} = SVX.VProgram_API.Nondet<{0}>();",
                            FormatTypeFullName(symTMethod.methodArgTypeFullNames[i]), inputVarName);
                    }
                    argVarNames.Add(inputVarName);
                }
                outputVarName = nextVar("msg");
                AppendFormattedLine("{0} {1} = {2}.{3}({4});",
                    FormatTypeFullName(symTMethod.methodReturnTypeFullName), outputVarName,
                    EmitParticipant(symTMethod.participantId),
                    symTMethod.methodName, string.Join(", ", argVarNames));
            }
            else if ((symTComposite = symT as SymTComposite) != null)
            {
                SymTTransfer rootTransfer;
                if (symTComposite.rootSymT is SymTNondet)
                {
                    // Nondet the root message and then overwrite the nested
                    // messages that we have information about.
                    outputVarName = EmitMessage(symTComposite.rootSymT, scope);
                    foreach (var entry in symTComposite.nestedSymTs)
                    {
                        string nestedVarName = EmitMessage(entry.symT, scope);
                        // Make sure we have a non-null parent to store the nested message in.
                        var lastDot = entry.fieldPath.LastIndexOf('.');
                        if (lastDot != -1)
                            AppendFormattedLine("System.Diagnostics.Contracts.Contract.Assume({0} != null);",
                                MakeFieldPathNullConditional(outputVarName, entry.fieldPath.Substring(0, lastDot),
                                symTComposite.MessageTypeFullName));
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
                    outputVarName = EmitMessage(symTComposite.rootSymT, scope);
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
                            RootSymTWithMessageId = new SymTNondet { messageTypeFullName = symTComposite.MessageTypeFullName },
                            nestedSymTs = symTComposite.nestedSymTs
                        }
                    }, scope);
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
                AppendFormattedLine("SVX.PrincipalHandle {0} = {1};", producerVarName, EmitPrincipalHandleOrNondet(symTTransfer.producer));
                outputVarName = nextVar("msg");
                AppendFormattedLine("{0} {1};", FormatTypeFullName(symTTransfer.MessageTypeFullName), outputVarName);
                AppendFormattedLine("if (SVX.VProgram_API.IsTrusted({0})) {{", producerVarName);
                {
                    IncreaseIndent();
                    string inputVarName = EmitMessage(symTTransfer.originalSymT, scope);
                    AppendFormattedLine("{0} = {1};", outputVarName, inputVarName);
                    // To maintain soundness of the model, update the metadata
                    // of nested messages the same way TransferNested would in
                    // production, even though we don't use their SymTs.
                    // XXX: symTTransfer.payloadSecretsVerifiedOnImport could
                    // contain non-message payload secrets once we support them,
                    // and we'd need to skip them here.
                    foreach (var entry in symTTransfer.payloadSecretsVerifiedOnImport)
                    {
                        string paramsPath = entry.fieldPath + ".theParams";
                        AppendFormattedLine("System.Diagnostics.Contracts.Contract.Assume({0} != null);",
                            MakeFieldPathNullConditional(outputVarName, paramsPath, symTTransfer.MessageTypeFullName));
                        AppendFormattedLine("SVX.SVX_Ops.TransferNested({0}.{1}, new {2}().Signer);",
                            outputVarName, paramsPath, FormatTypeFullName(entry.secretGeneratorTypeFullName));
                    }
                    DecreaseIndent();
                }
                AppendFormattedLine("}} else {{");
                {
                    IncreaseIndent();
                    string inputVarName = EmitMessage(symTTransfer.fallback ??
                        new SymTNondet { messageTypeFullName = symTTransfer.MessageTypeFullName }, scope);
                    AppendFormattedLine("{0} = {1};", outputVarName, inputVarName);
                    DecreaseIndent();
                }
                AppendFormattedLine("}}");

                // Should we introduce a "transfer info" object that we can both
                // use as an arg to Transfer and store in the SymTTransfer, to
                // avoid shuttling individual arguments back and forth?  The
                // following is not too bad.
                if (symTTransfer.hasSender)
                {
                    // Note: Transfer does not use the realRequestProducer arg in the vProgram.
                    AppendFormattedLine("SVX.SVX_Ops.Transfer({0}, {1}, {2}, null, {3});",
                        outputVarName, producerVarName, EmitPrincipalHandleOrNondet(symTTransfer.sender),
                        // http://stackoverflow.com/a/491367 :/
                        symTTransfer.browserOnly.ToString().ToLower());
                }
                else
                {
                    AppendFormattedLine("SVX.SVX_Ops.TransferNested({0}, {1});",
                        outputVarName, producerVarName);
                }

                // If we verified secrets on import, they are valid regardless
                // of whether the transfer was trusted.
                foreach (var entry in symTTransfer.payloadSecretsVerifiedOnImport)
                {
                    // I'm unsure of BCT handling of null dereferences in
                    // general, but here we can definitely assume non-null.
                    AppendFormattedLine("System.Diagnostics.Contracts.Contract.Assume({0} != null);",
                        MakeFieldPathNullConditional(outputVarName, entry.fieldPath, symTTransfer.MessageTypeFullName));
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
                    AppendFormattedLine("SVX.VProgram_API.AssumeValidSecret({0}.{1}.secretValue, " +
                        "{0}.{1}.theParams, new {2}().GetReaders({0}.{1}.theParams));",
                        outputVarName, entry.fieldPath, FormatTypeFullName(entry.secretGeneratorTypeFullName));
                }

                if (symTTransfer.hasSender)
                {
                    Type messageType = GetTypeByFullName(symTTransfer.MessageTypeFullName);
                    foreach (var acc in FieldFinder<Secret>.FindFields(messageType, true))
                    {
                        AppendFormattedLine("SVX.VProgram_API.AssumeBorne({0}.SVX_producer, {1});",
                            outputVarName, MakeFieldPathNullConditional(outputVarName, acc.path + ".secretValue",
                            symTTransfer.MessageTypeFullName));
                        AppendFormattedLine("SVX.VProgram_API.AssumeBorne({0}.SVX_sender, {1});",
                            outputVarName, MakeFieldPathNullConditional(outputVarName, acc.path + ".secretValue",
                            symTTransfer.MessageTypeFullName));
                    }
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

            AppendFormattedLine("SVX.VProgram_API.InitVProgram();");

            sb.AppendLine();

            participantsSeen.Add(certReq.participantId);
            participantsSeen.UnionWith(certReq.predicateParticipants);
            ScanParticipants(certReq.scrutineeSymT);
            foreach (var participant in participantsSeen)
                AppendFormattedLine("SVX.VProgram_API.CreateParticipant({0}, new {1}({0}));",
                    EmitPrincipal(participant.principal), FormatTypeFullName(participant.typeFullName));

            sb.AppendLine();

            string scrutineeVarName = EmitMessage(certReq.scrutineeSymT, null /* scope initially empty */);

            sb.AppendLine();

            AppendFormattedLine("SVX.VProgram_API.InPredicate = true;");
            // We list System.Diagnostics.Contracts as a direct dependency as a
            // good practice, even though we'll nearly always get it as an
            // indirect dependency.
            AppendFormattedLine("System.Diagnostics.Contracts.Contract.Assert({0}.{1}({2}));",
                EmitParticipant(certReq.participantId), certReq.methodName, scrutineeVarName);

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
