using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Reflection;
using Newtonsoft.Json;
using System.Runtime.CompilerServices;
using System.Diagnostics.Contracts;
using System.Threading;
using System.Collections.Concurrent;

[assembly: InternalsVisibleTo("VProgram")]

namespace SVX
{
    public class ParticipantId
    {
        public readonly Principal principal;
        public readonly Type type;

        public ParticipantId(Principal principal, Type type)
        {
            this.principal = principal;
            this.type = type;
        }

        public static ParticipantId Of(Participant participant)
        {
            return new ParticipantId(participant.SVX_Principal, participant.GetType());
        }
    }

    public static class SVX_Ops
    {
        public static void Init()
        {
            // Nothing yet.
        }

        public static ParticipantId ParticipantIdOf(Participant p) =>
            new ParticipantId(p.SVX_Principal, p.GetType());

        [BCTOmit]
        private static SymT GatherUsefulSymTs(SVX_MSG msg)
        {
            // Want to warn if the msg is inactive but has a symT set, at least
            // for the root message (possible developer mistake)?
            SymT rootSymT = msg.active ? (SymT)msg.SVX_symT : null;

            var nestedSymTs = (
                // NOTE: This will traverse into PayloadSecrets that contain
                // messages, which is what we want.
                from acc in FieldFinder<SVX_MSG>.FindFields(msg.GetType(),
                    // We do our own recursion in matches.
                    false)
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
        [BCTOmit]
        private static SymT GatherSymTs(SVX_MSG msg)
        {
            return GatherUsefulSymTs(msg) ??
                new SymTNondet { messageTypeFullName = msg.GetType().FullName };
        }

        [BCTOmit]
        private static void RecordCall(SVX_MSG output, Delegate del, SymT[] inputSymTs)
        {
            Participant participant = del.Target as Participant;
            if (participant == null)
                throw new ArgumentException("Delegate must belong to an SVX participant object");
            MethodInfo mi = del.GetMethodInfo();
            output.SVX_symT = new SymTMethod
            {
                participantId = new SymTParticipantId
                {
                    principal = participant.SVX_Principal,
                    typeFullName = participant.GetType().FullName
                },
                // XXX Verify that method is unique and doesn't use generics?
                methodName = mi.Name,
                methodReturnTypeFullName = mi.ReturnType.FullName,
                methodArgTypeFullNames = (from p in mi.GetParameters() select p.ParameterType.FullName).ToArray(),
                inputSymTs = inputSymTs,
            };
            output.active = true;
        }

        // Only take SymTs from call arguments that are statically (not
        // dynamically) messages.  This is more predictable (maybe) and
        // consistent with the scan for nested messages.
        private static SymT ScanArg<TArg>(TArg arg)
        {
            return typeof(SVX_MSG).IsAssignableFrom(typeof(TArg))
                ? GatherSymTs((SVX_MSG)(object)arg) : null;
        }

        // Note: SVX will automatically detect based on message IDs if a later
        // argument resulted from a sequence of operations on an earlier
        // argument, but not the other way around.
        public static TResult Call<T1, TResult>(Func<T1, TResult> f, T1 arg1)
            where TResult : SVX_MSG
        {
            var output = f(arg1);
            if (!VProgram_API.InVProgram)
            {
                var inputSymTs = new SymT[1];
                inputSymTs[0] = ScanArg(arg1);
                RecordCall(output, f, inputSymTs);
            }
            return output;
        }
        public static TResult Call<T1, T2, TResult>(Func<T1, T2, TResult> f, T1 arg1, T2 arg2)
            where TResult : SVX_MSG
        {
            var output = f(arg1, arg2);
            if (!VProgram_API.InVProgram)
            {
                var args = new SymT[2];
                args[0] = ScanArg(arg1);
                args[1] = ScanArg(arg2);
                RecordCall(output, f, args);
            }
            return output;
        }

        public static void FakeCall<T1, TResult>(Func<T1, TResult> f, T1 arg1, TResult output)
            where TResult : SVX_MSG
        {
            // XXX: Assert that this is not called from vProgram.
            var args = new SymT[1];
            args[0] = ScanArg(arg1);
            RecordCall(output, f, args);
        }
        public static void FakeCall<T1, T2, TResult>(Func<T1, T2, TResult> f, T1 arg1, T2 arg2, TResult output)
            where TResult : SVX_MSG
        {
            // XXX: Assert that this is not called from vProgram.
            var args = new SymT[2];
            args[0] = ScanArg(arg1);
            args[1] = ScanArg(arg2);
            RecordCall(output, f, args);
        }

        [BCTOmit]
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

        private static ConcurrentDictionary<CertificationRequest, bool> certificationCache = new ConcurrentDictionary<CertificationRequest, bool>();

        // Will be called from translated assemblies.  Only once we have
        // as-needed translation will we be able to omit the declaration.
        [BCTOmitImplementation]
        public static void Certify<TMsg>(TMsg msg, Predicate<TMsg> predicate,
            // params is convenient for now.  Think if it's appropriate long-term.
            params ParticipantId[] predicateParticipants)
            where TMsg : SVX_MSG
        {
            // Letting predicates be hosted by participants just like methods
            // seems to be the most reasonable way to pass configuration in.
            Participant participant = predicate.Target as Participant;
            if (participant == null)
                throw new ArgumentException("Delegate must belong to an SVX participant object");
            MethodInfo mi = predicate.GetMethodInfo();

            var scrutineeSymT = GatherSymTs(msg);
            // Clean up for cacheability.
            scrutineeSymT = new SymTCleaner().Rewrite(scrutineeSymT);

            var c = new CertificationRequest {
                scrutineeSymT = scrutineeSymT,
                participantId = new SymTParticipantId
                {
                    principal = participant.SVX_Principal,
                    typeFullName = participant.GetType().FullName
                },
                methodName = mi.Name,
                methodArgTypeFullName = typeof(TMsg).FullName,
                predicateParticipants = predicateParticipants.Select(
                    (t) => new SymTParticipantId { principal = t.principal, typeFullName = t.type.FullName }).ToArray(),
            };

            // Basic implementation of certification caching.  In the future, we
            // may want fancier things, e.g., expiration, persistence, etc.
            if (!certificationCache.GetOrAdd(c, LocalCertifier.Certify))
                // TODO: Custom exception type
                throw new Exception("SVX certification failed.");
        }

        // In support of old examples.  Won't be part of the real SVX API.
        public static void TransferForTesting(SVX_MSG msg, PrincipalHandle producer, PrincipalHandle sender)
        {
            Transfer(msg, producer, sender, null, false);
        }

        [BCTOmit]
        class ProducerReplacer
        {
            internal PrincipalHandle oldProducer, newProducer;
            internal SymT Rewrite(SymT symT)
            {
                var symTTransfer = symT as SymTTransfer;
                if (symTTransfer != null && symTTransfer.producer == oldProducer)
                    symT = new SymTTransfer(symTTransfer) { producer = newProducer };
                return symT.RewriteEmbeddedSymTs(Rewrite);
            }
        }

        // Crashes the CCI unstacker. :(
        [BCTOmitImplementation]
        private static void TransferProd(SVX_MSG msg, PrincipalHandle producer, PrincipalHandle sender, PrincipalHandle realRequestProducer, bool browserOnly)
        {
            var originalSymT = (SymT)msg.SVX_symT ?? new SymTNondet { messageTypeFullName = msg.GetType().FullName };

            // XXX Warn if one is set and the other isn't?
            if (realRequestProducer != null && msg.SVX_placeholderRequestProducer != null)
            {
                // Replace the server-issued facet with the real principal.  We
                // could also strip the SymTTransfer layers, but this should
                // leave it clearer what happened.

                // If we try to define ProducerReplacer as a lambda, we get "Use
                // of unassigned local variable" on the recursive call.
                originalSymT = new ProducerReplacer
                {
                    oldProducer = msg.SVX_placeholderRequestProducer,
                    newProducer = realRequestProducer
                }.Rewrite(originalSymT);
            }

            msg.SVX_symT = new SymTTransfer
            {
                originalSymT = originalSymT,
                producer = producer,
                sender = sender,
                hasSender = true,
                browserOnly = browserOnly
            };
            msg.active = true;
        }

        internal static void Transfer(SVX_MSG msg, PrincipalHandle producer, PrincipalHandle sender,
            PrincipalHandle realRequestProducer, bool browserOnly)
        {
            if (producer == null || sender == null)
                // Auto-generate them instead?  But we'd need to know the issuer.
                // We may eventually have a global variable for the current party.
                throw new ArgumentNullException();

            if (VProgram_API.InVProgram)
            {
                if (browserOnly)
                    Contract.Assume(!VProgram_API.ActsFor(sender, VProgram_API.trustedServerPrincipal));
            }
            else
            {
                TransferProd(msg, producer, sender, realRequestProducer, browserOnly);
            }

            // Make the same metadata changes in the vProgram as in production.
            msg.SVX_producer = producer;
            msg.SVX_sender = sender;
            msg.SVX_placeholderRequestProducer = null;
        }

        // Crashes the CCI unstacker. :(
        [BCTOmitImplementation]
        private static void TransferNestedProd(SVX_MSG msg, PrincipalHandle producer)
        {
            msg.SVX_symT = new SymTTransfer
            {
                originalSymT = (SymT)msg.SVX_symT ?? new SymTNondet { messageTypeFullName = msg.GetType().FullName },
                producer = producer,
                hasSender = false
            };
            msg.active = true;
        }

        internal static void TransferNested(SVX_MSG msg, PrincipalHandle producer)
        {
            if (producer == null)
                // Auto-generate it instead?  But we'd need to know the issuer.
                // We may eventually have a global variable for the current party.
                throw new ArgumentNullException();

            if (!VProgram_API.InVProgram)
            {
                TransferNestedProd(msg, producer);
            }

            // Make the same metadata changes in the vProgram as in production.
            msg.SVX_producer = producer;
            // Do not change sender.
            msg.SVX_placeholderRequestProducer = null;
        }

        internal static void WipeActiveFlags(SVX_MSG msg)
        {
            if (msg != null)
            {
                msg.active = false;
                // FIXME: What if a field contains an object whose dynamic type
                // contains more nested messages than the static type of the
                // field?  We should fix this for all FieldFinder callers at
                // once. ~ matt@mattmccutchen.net 2016-08-16
                foreach (var acc in FieldFinder<SVX_MSG>.FindFields(msg.GetType(),
                    // We do our own recursion in matches since it's cleaner.
                    false))
                {
                    WipeActiveFlags(acc.nullConditionalGetter(msg));
                }
            }
        }

        // Run the action in the VProgram only.  Meant for actions that have no
        // side effects on production (e.g., declaring predicates) and may rely
        // on data not available in production (e.g., underlying principals).
        // TODO: Better enforce the lack of side effects.
        // TODO: As long as we can't handle compiler-generated closures, want to
        // provide a few more overloads of this method to pass arguments?
        public static void Ghost(Action a)
        {
            if (VProgram_API.InVProgram)
                a();
        }
    }

}
