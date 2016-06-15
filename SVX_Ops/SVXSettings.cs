using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace SVX
{
    public class SVXSettings
    {
        // Must be set before any SVX_Ops things are constructed.
        public static SVXSettings settings;

        public string MyPartyName;
        public string[] TrustedParties;

        // We do not yet have a certification server compatible with the current
        // version of SVAuth, so better leave this set to true.
        public bool CertifyLocally;

        // Folder for SVX data.  Will be automatically created if it doesn't exist.
        public string SVXFolderPath;

        // Certification server settings:

        public string DLLServerAddress;
        public string Token;

        // Local certification settings:

        // I'm not sure how this setting worked in the original AuthPlatelet,
        // but here it's /just/ a parent directory for temporary VPrograms.  The
        // VProgram skeleton is bundled with SVAuth.  It doesn't seem there's
        // any benefit to allowing this to be customized? ~ t-mattmc@microsoft.com 2016-06-10
        public string VProgramPath => Path.Combine(SVXFolderPath, "vProgram");

        // If true, keep temporary VPrograms after verification for debugging
        // purposes.
        public bool KeepVPrograms = true;

        // TODO: Document how to set up a Poirot enlistment.
        public string PoirotRoot;

        // Misc:

        // This is so much more sensible than duplicating the logic many places
        // in SVX_Ops.  We can make these nonpublic if we care.  Ideally we'd
        // have a framework to memoize these and take care of the lifetime
        // issues, but it's just not worth worrying about. ~ t-mattmc@microsoft.com 2016-06-03
        public string methodsFolder => Path.Combine(SVXFolderPath, "methods");
        public string dllsFolder => Path.Combine(SVXFolderPath, "dlls");
    }
}
