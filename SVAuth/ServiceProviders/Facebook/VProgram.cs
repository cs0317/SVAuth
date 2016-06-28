// This file is excluded from the build of the SVAuth project, but it's still a
// C# file so we get syntax highlighting, etc.

using System.Diagnostics.Contracts;

namespace SVAuth.VProgram
{

    class GlobalObjectsForSVX : GenericAuth.GlobalObjects_base
    {
        static public void init(OAuth20.NondetOAuth20 Nondet)
        {
            AS = new ServiceProviders.Facebook.Facebook_IdP_Default();
            RP = new ServiceProviders.Facebook.Facebook_RP(Nondet.String(), Nondet.String(), Nondet.String(), Nondet.String(), Nondet.String(), Nondet.String());
        }
    }
    class PoirotMain
    {
        // BCT treats the methods of NondetOAuth20 as nondeterministic since the
        // program contains no subclasses that implement them; it doesn't care
        // if the receiver is null.  Set this field to null explicitly so the C#
        // compiler doesn't warn that it is never set.
        public static OAuth20.NondetOAuth20 Nondet = null;

        static void Main()
        {
            GlobalObjectsForSVX.init(Nondet);
            SVX.SVX_MSG m = Nondet.SVX_MSG();
            Contract.Assume(m.GetType() == typeof(GenericAuth.SignInIdP_Req));
            GlobalObjectsForSVX.SignInIdP_Req = (GenericAuth.SignInIdP_Req)m;
            SynthesizedPortion.SynthesizedSequence();
        }
    }

}
