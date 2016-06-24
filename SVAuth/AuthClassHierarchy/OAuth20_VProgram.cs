// This file is excluded from the build of the SVAuth project, but it's still a
// C# file so we get syntax highlighting, etc.

namespace SVAuth.VProgram
{

    class GlobalObjectsForSVX : GenericAuth.GlobalObjects_base
    {
        static public void init()
        {
            AS = new OAuth20.DummyConcreteAuthorizationServer();
            RP = new ServiceProviders.Facebook.Facebook_RP();
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
            GlobalObjectsForSVX.init();
            SynthesizedPortion.SynthesizedSequence();
        }
    }

}
