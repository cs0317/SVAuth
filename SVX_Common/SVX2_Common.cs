using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SVX2
{
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

    interface Nondet
    {
        T Nondet<T>();
    }
    public static class VProgram_API
    {
        // TODO: Change to Dictionary<Tuple<string, Type>, object> (or a
        // custom class in place of Tuple) once we have suitable stubs to
        // compare the keys by value.
        static Dictionary<string, Dictionary<Type, object>> participants = new Dictionary<string, Dictionary<Type, object>>();

        public static T GetParticipant<T>(string participantId) where T : new()
        {
            Dictionary<Type, object> dict1;
            // FIXME: TryGetValue doesn't have a stub and is being treated as
            // nondet every time.  It doesn't matter yet.
            if (!participants.TryGetValue(participantId, out dict1))
            {
                dict1 = new Dictionary<Type, object>();
                participants.Add(participantId, dict1);
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

        public static T Nondet<T>()
        {
            return ((Nondet)null).Nondet<T>();
        }
    }
}
