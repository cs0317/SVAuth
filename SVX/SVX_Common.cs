using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("SVX_Ops")]
[assembly: InternalsVisibleTo("VProgram")]

// BE CAREFUL if you rename anything in this file.  VProgramGenerator refers to
// many things in SVX_Common and unfortunately doesn't use nameof/typeof because
// it would just be too much clutter.

namespace SVX
{
    // Doing the completely naive thing for now: mutable fields.
    public class SVX_MSG
    {
        // Currently not serialized.  See comment at the top of SymT.cs.
        //[JsonProperty(ItemTypeNameHandling = TypeNameHandling.All)]
        internal SymT SVX_symT;

        // Better ideas? ~ t-mattmc@microsoft.com 2016-07-27
        //[JsonIgnore]
        //public bool SVX_serializeSymT = true;
        //public bool ShouldSerializeSVX_symT() => SVX_serializeSymT;

        // Fields that are set on import so they can be used from SVX methods.
        // These will usually be null in messages being exported; if so, they
        // should be omitted for cleanliness.
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public PrincipalHandle SVX_producer, SVX_sender;

        // This field is currently used for direct responses only to pass the
        // server-generated client facet back to the client.  It is set on
        // export and cleared on import (and used only by ImportDirectResponse).
        // It is public for serialization but shouldn't otherwise be manipulated
        // by protocol code.
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public PrincipalHandle SVX_placeholderRequestProducer;

        // True if we know the symT is valid from our point of view.  When a
        // message is imported, the developer will set the symT field to the
        // received symT and then call Import, which will add the proper
        // SymTTransfer.  If the developer tries to use the message without
        // finishing the import, this flag will stop us from honoring the
        // received symT literally.
        // TODO: Of course we should also restrict mutations to the symT, but
        // we're not worrying much about mutability anywhere right now.
        //
        // This field is non-public, so it won't be serialized by Json.NET by
        // default, which is what we want.
        internal bool active;

        public SVX_MSG()
        {
            SVX_producer = null;
            SVX_sender = null;
            SVX_symT = null;
            active = false;
        }
    }

    // We might be able to get away without translating this, but it's fine to translate too.
    public class Participant
    {
        public Principal SVX_Principal { get; }

        public Participant(Principal principal)
        {
            SVX_Principal = principal;
        }

        // Concrete participant classes must have a constructor of the form:
        //
        // MyParticipant(Principal principal);
        //
        // which will be used to instantiate them in the vProgram, passing in
        // the principal originally returned by SVX_Principal.  Eventually, we
        // want to support recording of arbitrary configuration parameters for
        // all objects that are instantiated in the vProgram, but in the
        // meantime, this is a bare minimum to let us create RPs with the real
        // RP principal without hard-coding it.  IdPs may still hard-code the
        // IdP principal and assert that the one passed is correct.
        //
        // (Currently, since the vProgram is emitted as C# source, constructors
        // with additional parameters that have defaults will work, but we may
        // change this in the future.)
    }

    // Types of assumptions we need to allow:
    // - acts for
    // - User-defined predicates that can be asserted by some party, e.g., SignedIn
    // - Certain parties don't call certain endpoints directly, e.g., RP does
    //   not call SignInIdP directly with someone else's state, which would
    //   break the XSRF property.  We should be able to enforce this.

    // We expect the following APIs to only be executed from the vProgram,
    // though there might be some cases for developer-written code that is only
    // executed from the vProgram to call them.  For now, put them in SVX_Common
    // to be translated by BCT, though we may eventually replace them all by
    // handwritten stubs.

    // Make these internal for now.  We'll see as we go which ones need to be
    // exposed to developers. ~ t-mattmc@microsoft.com 2016-07-08

    public static class VProgram_API
    {
        internal static bool InVProgram = false;
        internal static bool InPredicate = false;

        // Don't AssumeActsFor until InVProgram is set correctly.  If we wanted
        // to be fancy, we could make InVProgram a property with different
        // implementations in .NET and extra_stubs.bpl.
        internal static void InitVProgram()
        {
            InVProgram = true;
            AssumeActsFor(trustedServerPrincipal, trustedPrincipal);
        }

        // TODO: Change to Dictionary<Tuple<string, Type>, object> (or a
        // custom class in place of Tuple) once we have suitable stubs to
        // compare the keys by value.
        static Dictionary<Principal, Dictionary<Type, object>> participants = new Dictionary<Principal, Dictionary<Type, object>>();

        public static T GetParticipant<T>(Principal principal)
        {
            return (T)GetParticipant(new ParticipantId(principal, typeof(T)));
        }

        public static object GetParticipant(ParticipantId id)
        {
            Dictionary<Type, object> dict1;
            if (!participants.TryGetValue(id.principal, out dict1))
            {
                dict1 = new Dictionary<Type, object>();
                participants[id.principal] = dict1;
            }
            object participantObj;
            if (!dict1.TryGetValue(id.type, out participantObj))
            {
                throw new NotImplementedException(
                    "Dynamic creation of participants is not implemented.  " +
                    "All participants of SVX method calls are created " +
                    "automatically at the beginning of the vProgram.  All " +
                    "participants used in the predicate that might not be " +
                    "used in a method call must be specified as " +
                    "predicateParticipants so they get created.");
                // As of 2016-07-26, we are calling a constructor with the
                // principal as a parameter, so we can no longer use
                // "T : new()".

                // XXX Strictly enforce that the public version of
                // GetParticipant can be called only in the predicate and only
                // on participants that were declared?  We may just implement
                // the "new T()" instead.

                // Apparently "new T()" compiles to
                // System.Activator.CreateInstance, which BCT doesn't support.
                // It would be a reasonable feature to add to BCT, but it's too
                // much work for the moment.
                // ~ t-mattmc@microsoft.com 2016-07-11

                // Now that this code is moved to a method that doesn't have T,
                // we would just use Activator.CreateInstance(id.type).
                //participant = new T();
                //dict1[typeof(T)] = participant;
            }
            return participantObj;
        }

        internal static void CreateParticipant<T>(Principal principal, T participant)
        {
            Dictionary<Type, object> dict1;
            if (!participants.TryGetValue(principal, out dict1))
            {
                dict1 = new Dictionary<Type, object>();
                participants[principal] = dict1;
            }
            // Assert not already there?
            dict1[typeof(T)] = participant;
        }

        [BCTOmitImplementation]
        private static T NondetImpl<T>()
        {
            throw new NotImplementedException();
        }

        // Stopgap to see how far we can get with the example.  Really, raw
        // nondet of a Ref is unsafe in BCT-based models: it can cause aliasing
        // and heap pollution.  We need to emit a custom nondet method for each
        // type. ~ t-mattmc@microsoft.com 2016-07-15
        //
        // Model IdPs now call this.  Consider restricting it later.
        // ~ t-mattmc@microsoft.com 2016-07-27
        public static T Nondet<T>()
        {
            T ret = NondetImpl<T>();
            Contract.Assume(ret.GetType() == typeof(T));
            return ret;
        }

        static Dictionary<PrincipalHandle, HashSet<PrincipalHandle>> actsForEdges = new Dictionary<PrincipalHandle, HashSet<PrincipalHandle>>();

        // Little breadth-first search.  Suggestions for a better library or
        // performance improvements welcome.
        //
        // In the vProgram, we definitely want to use the SMT solver's support
        // for reasoning about partial orders rather than having Corral unroll
        // this code.
        static HashSet<PrincipalHandle> GetAllowedTargets(PrincipalHandle actor)
        {
            var ret = new HashSet<PrincipalHandle>();
            var q = new Queue<PrincipalHandle>();
            Action<PrincipalHandle> Visit = (ph) =>
            {
                if (!ret.Contains(ph))
                {
                    ret.Add(ph);
                    q.Enqueue(ph);
                }
            };
            Visit(actor);
            while (q.Count > 0)
            {
                var ph = q.Dequeue();
                HashSet<PrincipalHandle> outEdges;
                if (actsForEdges.TryGetValue(ph, out outEdges))
                {
                    foreach (var ph2 in outEdges)
                        Visit(ph2);
                }
            }
            return ret;
        }

        // This is the idealized global ActsFor.  If we allowed it to return
        // false when called from an SVX method in prod, but true in the
        // vProgram because of an AssumeActsFor by another party, we'd have
        // unsoundness, so for simplicity we don't allow it to be called in prod
        // at all.
        [BCTOmitImplementation]
        public static bool ActsFor(PrincipalHandle actor, PrincipalHandle target)
        {
            throw new NotImplementedException();
        }

        public static bool ActsForAny(PrincipalHandle actor, PrincipalHandle[] targets)
        {
            // I'd like to write the following, but BCT can't handle it for
            // several reasons.  Not worth worrying about at the moment.
            // ~ t-mattmc@microsoft.com 2016-07-05
            //targets.Any((target) => ActsFor(actor, target));

            foreach (var target in targets)
                if (ActsFor(actor, target))
                    return true;
            return false;
        }

        // OK, this really doesn't belong in VProgram_API... fix it later.
        internal static bool KnownActsForAny(PrincipalHandle actor, PrincipalHandle[] targets)
        {
            var allowedTargets = GetAllowedTargets(actor);
            return targets.Any((target) => allowedTargets.Contains(target));
        }

        // For testing purposes.  This may not be the final form of this API,
        // but we will definitely provide some wrapper around Contract.Assume
        // because every call to Contract.Assume has the potential to compromise
        // the verification if the developer doesn't know exactly what they're
        // doing.
        // XXX: This does not really belong in VProgram_API, because it will
        // have an effect on secrets read enforcement in production.
        public static void AssumeActsFor(PrincipalHandle actor, PrincipalHandle target)
        {
            if (InVProgram)
                Contract.Assume(ActsFor(actor, target));
            else
            {
                HashSet<PrincipalHandle> outEdges;
                if (!actsForEdges.TryGetValue(actor, out outEdges))
                {
                    outEdges = new HashSet<PrincipalHandle>();
                    actsForEdges.Add(actor, outEdges);
                }
                outEdges.Add(target);  // OK if it was already there
            }
        }

        [BCTOmitImplementation]
        private static void AssumeBorneImpl(PrincipalHandle bearer, string secretValue)
        {
            // Should only be called by emitted vProgram code.
            throw new NotImplementedException();
        }

        // Wrapper: the easiest way to get BCT to record the arguments.
        internal static void AssumeBorne(PrincipalHandle bearer, string secretValue)
        {
            AssumeBorneImpl(bearer, secretValue);
        }

        [BCTOmitImplementation]
        private static void AssumeTokenParamsImpl(string tokenValue, object theParams)
        {
            // Does nothing in production.
        }

        [BCTOmitImplementation]
        private static void AssumeAuthenticatesBearerImpl(string secretValue, PrincipalHandle[] originalReaders)
        {
            // Does nothing in production.
        }

        internal static void AssumeValidToken(string tokenValue, object theParams)
        {
            AssumeTokenParamsImpl(tokenValue, theParams);
        }

        // Wrapper: the easiest way to get BCT to record the arguments.
        internal static void AssumeValidSecret(string secretValue, object theParams, PrincipalHandle[] originalReaders)
        {
            // Just get BCT to record the readers.
            if (InVProgram)
            {
                foreach (var reader in originalReaders)
                {
                    var readerIsTrusted = IsTrusted(reader);
                }
            }
            AssumeTokenParamsImpl(secretValue, theParams);
            AssumeAuthenticatesBearerImpl(secretValue, originalReaders);
        }

        // Substitute for Contract.Assert in SVX-recorded code.  TODO explain.
        public static void Assert(bool condition)
        {
            if (InVProgram)
                Contract.Assume(condition);
            else
                Contract.Assert(condition);
        }

        [BCTOmitImplementation]
        public static Principal UnderlyingPrincipal(PrincipalHandle ph)
        {
            throw new NotImplementedException();
        }

        // The principals that act for __trusted are trusted for the purpose of
        // the current verification.  Saves us from axiomatizing separately that
        // if we trust a principal, we trust everyone who acts for them.
        internal static Principal trustedPrincipal = Principal.Of("__trusted");

        // This principal has no meaning except to define a set of trusted
        // servers that is closed under acts-for.
        internal static Principal trustedServerPrincipal = Principal.Of("__trustedServer");

        internal static bool IsTrusted(PrincipalHandle ph)
        {
            return ActsFor(ph, trustedPrincipal);
        }

        public static void AssumeTrusted(PrincipalHandle ph)
        {
            if (!InPredicate)
                throw new InvalidOperationException("Trust assumptions may only be made from the predicate.");
            Contract.Assume(IsTrusted(ph));
        }

        [BCTOmitImplementation]
        private static void AssumeNoOneElseActsFor(PrincipalHandle ph)
        {
            throw new NotImplementedException();
        }

        // No other principal may act for the underlying principal of the browser.
        public static void AssumeTrustedBrowser(PrincipalHandle ph)
        {
            AssumeTrusted(ph);  // checks InPredicate
            AssumeNoOneElseActsFor(ph);
        }

        // No one who acts for a trusted server may be sender of a message with
        // a "browser only" message structure.  Of course, trusted servers may
        // /produce/ such messages.
        public static void AssumeTrustedServer(PrincipalHandle ph)
        {
            if (!InPredicate)
                throw new InvalidOperationException("Trust assumptions may only be made from the predicate.");
            Contract.Assume(ActsFor(ph, trustedServerPrincipal));
        }
    }
}
