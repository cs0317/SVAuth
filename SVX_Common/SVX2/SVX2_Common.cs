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

namespace SVX2
{
    // Doing the completely naive thing for now: mutable fields.
    public class SVX_MSG
    {
        // We don't want to translate all the SymT code; neither do we want a
        // dependency from SVX_Common to SVX_Ops, or to make another assembly.
        // So use object. :/
        // This will go away once we merge SVX_Common and SVX_Ops into one
        // assembly and use BCT attributes to control what gets translated.

        // FIXME: Restrict the possible types of SymTs before exposing this to
        // untrusted input.  I can't justify the time to implement the
        // restriction yet. ~ t-mattmc@microsoft.com 2016-07-14
        [JsonProperty(TypeNameHandling = TypeNameHandling.All)]
        public object /*SymT*/ SVX_symT;

        // These will usually be null in messages being transferred; if so, they
        // should be omitted for cleanliness.
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public PrincipalHandle SVX_producer, SVX_sender;

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
    public interface Participant
    {
        Principal SVXPrincipal { get; }
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

        // TODO: Change to Dictionary<Tuple<string, Type>, object> (or a
        // custom class in place of Tuple) once we have suitable stubs to
        // compare the keys by value.
        static Dictionary<Principal, Dictionary<Type, object>> participants = new Dictionary<Principal, Dictionary<Type, object>>();

        internal static T GetParticipant<T>(Principal principal) where T : new()
        {
            Dictionary<Type, object> dict1;
            if (!participants.TryGetValue(principal, out dict1))
            {
                dict1 = new Dictionary<Type, object>();
                participants[principal] = dict1;
            }
            object participantObj;
            T participant;
            if (dict1.TryGetValue(typeof(T), out participantObj))
            {
                participant = (T)participantObj;
            }
            else
            {
                throw new NotImplementedException(
                    "Dynamic creation of participants is not implemented.  " +
                    "All participants of SVX method calls are created " +
                    "automatically at the beginning of the vProgram.  All " +
                    "participants used in the predicate that might not be " +
                    "used in a method call must be specified as " +
                    "predicateParticipants so they get created.");
                // Apparently "new T()" compiles to
                // System.Activator.CreateInstance, which BCT doesn't support.
                // It would be a reasonable feature to add to BCT, but it's too
                // much work for the moment.
                // ~ t-mattmc@microsoft.com 2016-07-11
                //participant = new T();
                //dict1[typeof(T)] = participant;
            }
            return participant;
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
        internal static T Nondet<T>()
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
        private static void AssumeValidSecretImpl(string secretValue, PrincipalHandle[] originalReaders)
        {
            // Does nothing in production.
        }

        // Wrapper: the easiest way to get BCT to record the arguments.
        internal static void AssumeValidSecret(string secretValue, PrincipalHandle[] originalReaders)
        {
            foreach (var reader in originalReaders)
            {
                // Just get BCT to record the reader.
            }
            AssumeValidSecretImpl(secretValue, originalReaders);
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
        internal static Principal UnderlyingPrincipal(PrincipalHandle ph)
        {
            throw new NotImplementedException();
        }
    }
}
