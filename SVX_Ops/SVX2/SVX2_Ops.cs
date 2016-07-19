using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Reflection;
using Newtonsoft.Json;
using Utils = SVX.Utils;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("VProgram")]

namespace SVX2
{
    public static class SVX_Ops
    {
        public static void Init()
        {

        }

        private static SymT GatherUsefulSymTs(SVX_MSG msg)
        {
            // Want to warn if the msg is inactive but has a symT set, at least
            // for the root message (possible developer mistake)?
            SymT rootSymT = msg.active ? (SymT)msg.SVX_symT : null;

            var nestedSymTs = (
                // NOTE: This will traverse into PayloadSecrets that contain
                // messages, which is what we want.
                from acc in FieldFinder<SVX_MSG>.FindFields(msg.GetType())
                let nestedMsg = acc.nullConditionalGetter(msg)
                where nestedMsg != null
                let nestedSymT = GatherUsefulSymTs(nestedMsg)
                where nestedSymT != null
                select new NestedSymTEntry { fieldPath = acc.path, symT = nestedSymT }
                ).ToArray();

            // As a simplification, don't unnecessarily create composites
            // (though it shouldn't break anything).  And if we have no
            // information, return null so an outer message doesn't
            // unnecessarily create a composite.

            if (nestedSymTs.Length == 0)
                return rootSymT;  // may be null

            if (rootSymT == null)
                rootSymT = new SymTNondet { messageTypeFullName = msg.GetType().FullName };

            return new SymTComposite {
                RootSymTWithMessageId = rootSymT,
                nestedSymTs = nestedSymTs
            };
        }
        private static SymT GatherSymTs(SVX_MSG msg)
        {
            return GatherUsefulSymTs(msg) ??
                new SymTNondet { messageTypeFullName = msg.GetType().FullName };
        }

        private static T FillSymT<T>(T msg, SymT symT) where T : SVX_MSG
        {
            msg.active = true;
            msg.SVX_symT = symT;
            return msg;
        }

        private static SymT MakeSymTForMethodCall(Delegate del, SymT[] inputSymTs)
        {
            Participant participant = del.Target as Participant;
            if (participant == null)
                throw new ArgumentException("Delegate must belong to an SVX participant object");
            MethodInfo mi = del.GetMethodInfo();
            return new SymTMethod {
                participantId = new ParticipantId {
                    principal = participant.SVXPrincipal,
                    typeFullName = participant.GetType().FullName
                },
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
        // Note: SVX will automatically detect based on message IDs if input2
        // resulted from a sequence of operations on input1, but not the other
        // way around.
        public static T Call<T1, T2, T>(Func<T1, T2, T> f, T1 input1, T2 input2)
            where T : SVX_MSG where T1 : SVX_MSG where T2 : SVX_MSG
        {
            return FillSymT(f(input1, input2), MakeSymTForMethodCall(f, new SymT[] { GatherSymTs(input1), GatherSymTs(input2) }));
        }

        class SymTCleaner
        {
            int nextNewMessageId = 0;
            Dictionary<string, string> messageIdMap = new Dictionary<string, string>();

            // Current policy.  TODO: make configurable.
            bool ShouldKeep(PrincipalHandle ph) => ph is Principal;

            PrincipalHandle Rewrite(PrincipalHandle ph) => ShouldKeep(ph) ? ph : null;
            internal SymT Rewrite(SymT symT)
            {
                if (!(symT is SymTComposite))
                {
                    string newMessageId;
                    if (!messageIdMap.TryGetValue(symT.messageId, out newMessageId))
                    {
                        newMessageId = (nextNewMessageId++).ToString();
                        messageIdMap[symT.messageId] = newMessageId;
                    }
                    symT.messageId = newMessageId;
                }
                var symTTransfer = symT as SymTTransfer;
                if (symTTransfer != null)
                    symT = new SymTTransfer(symTTransfer) {
                        producer = Rewrite(symTTransfer.producer),
                        sender = Rewrite(symTTransfer.sender),
                    };
                return symT.RewriteEmbeddedSymTs(Rewrite);
            }
        }

        public static void Certify<T>(T msg, Func<T, bool> predicate, Principal[] trustedParties,
            Tuple<Principal, Type>[] predicateParticipants = null)
            where T : SVX_MSG
        {
            if (predicate.Target != null)
                // For now.  As long as we allow participants on SVX method
                // calls, it wouldn't be bad to allow them here too.
                throw new ArgumentException("Predicate must be a static method");
            if (predicateParticipants == null)
                predicateParticipants = new Tuple<Principal, Type>[0];

            var scrutineeSymT = GatherSymTs(msg);
            // Clean up for cacheability.
            scrutineeSymT = new SymTCleaner().Rewrite(scrutineeSymT);
            MethodInfo mi = predicate.GetMethodInfo();

            var c = new CertificationRequest {
                scrutineeSymT = scrutineeSymT,
                methodName = mi.Name,
                methodDeclaringTypeFullName = mi.DeclaringType.FullName,
                methodArgTypeFullName = mi.GetParameters()[0].ParameterType.FullName,
                predicateParticipants = predicateParticipants.Select(
                    (t) => new ParticipantId { principal = t.Item1, typeFullName = t.Item2.FullName }).ToArray(),
                // XXX Establish a style guide for passing lists around.
                trustedParties = trustedParties.ToArray()
            };

            // TODO: Cache based on c.  Means we need to implement Equals/GetHashCode.
            if (!LocalCertifier.Certify(c))
                // TODO: Custom exception type
                throw new Exception("SVX certification failed.");
        }

        // In support of old examples.  Won't be part of the real SVX API.
        public static void TransferForTesting(SVX_MSG msg, PrincipalHandle producer, PrincipalHandle sender)
        {
            Transfer(msg, producer, sender, null);
        }

        class ProducerReplacer
        {
            internal PrincipalHandle placeholderDirectClient, realDirectClient;
            internal SymT Rewrite(SymT symT)
            {
                var symTTransfer = symT as SymTTransfer;
                if (symTTransfer != null && symTTransfer.producer == placeholderDirectClient)
                    symT = new SymTTransfer(symTTransfer) { producer = realDirectClient };
                return symT.RewriteEmbeddedSymTs(Rewrite);
            }
        }

        internal static void Transfer(SVX_MSG msg, PrincipalHandle producer, PrincipalHandle sender, PrincipalHandle realDirectClient)
        {
            if (producer == null || sender == null)
                // Auto-generate them instead?  But we'd need to know the issuer.
                // We may eventually have a global variable for the current party.
                throw new ArgumentNullException();

            var originalSymT = (SymT)msg.SVX_symT ?? new SymTNondet { messageTypeFullName = msg.GetType().FullName };

            // XXX Warn if one is set and the other isn't?
            if (realDirectClient != null && msg.SVX_directClient != null)
            {
                // Replace the server-issued facet with the real principal.  We
                // could also strip the SymTTransfer layers, but this should
                // leave it clearer what happened.

                // If we try to define ProducerReplacer as a lambda, we get "Use
                // of unassigned local variable" on the recursive call.
                originalSymT = new ProducerReplacer {
                    placeholderDirectClient = msg.SVX_directClient,
                    realDirectClient = realDirectClient
                }.Rewrite(originalSymT);
            }

            msg.SVX_producer = producer;
            msg.SVX_sender = sender;
            msg.SVX_directClient = null;
            msg.SVX_symT = new SymTTransfer {
                originalSymT = originalSymT,
                producer = producer,
                sender = sender,
                hasSender = true
            };
            msg.active = true;
        }

        internal static void TransferNested(SVX_MSG msg, PrincipalHandle producer)
        {
            if (producer == null)
                // Auto-generate it instead?  But we'd need to know the issuer.
                // We may eventually have a global variable for the current party.
                throw new ArgumentNullException();
            msg.SVX_producer = producer;
            // Do not change sender.
            msg.SVX_directClient = null;
            msg.SVX_symT = new SymTTransfer
            {
                originalSymT = (SymT)msg.SVX_symT ?? new SymTNondet { messageTypeFullName = msg.GetType().FullName },
                producer = producer,
                hasSender = false
            };
            msg.active = true;
        }
    }

}
