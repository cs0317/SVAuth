using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("SVX_Ops")]

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
        internal object /*SymT*/ symT;
        public PrincipalHandle producer, sender;

        public SVX_MSG()
        {
            producer = null;
            sender = null;
            symT = null;
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

    public static class VProgram_API
    {
        // TODO: Change to Dictionary<Tuple<string, Type>, object> (or a
        // custom class in place of Tuple) once we have suitable stubs to
        // compare the keys by value.
        static Dictionary<Principal, Dictionary<Type, object>> participants = new Dictionary<Principal, Dictionary<Type, object>>();

        public static T GetParticipant<T>(Principal principal) where T : new()
        {
            Dictionary<Type, object> dict1;
            // FIXME: TryGetValue doesn't have a stub and is being treated as
            // nondet every time.  It doesn't matter yet.
            if (!participants.TryGetValue(principal, out dict1))
            {
                dict1 = new Dictionary<Type, object>();
                participants.Add(principal, dict1);
            }
            object participantObj;
            T participant;
            if (dict1.TryGetValue(typeof(T), out participantObj))
            {
                participant = (T)participantObj;
            }
            else
            {
                participant = new T();
                dict1.Add(typeof(T), participant);
            }
            return participant;
        }

        [BCTOmitImplementation]
        public static T Nondet<T>()
        {
            throw new NotImplementedException();
        }

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

        [BCTOmitImplementation]
        public static Principal UnderlyingPrincipal(PrincipalHandle ph)
        {
            throw new NotImplementedException();
        }
    }
}
