using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace SVX
{
    [BCTOmit]
    public class SVXSettings
    {
        // Must be set before any SVX_Ops things are constructed.
        public static SVXSettings settings;

        // We do not yet have a certification server compatible with the current
        // version of SVAuth.
        //public bool CertifyLocally;

        // Folder for SVX runtime data.  Will be automatically created if it doesn't exist.
        // May be relative to working directory, assumed to be SVAuth project directory.
        public string SVXFolderPath;

        // Local certification settings:

        // I'm not sure how this setting worked in the original AuthPlatelet,
        // but here it's /just/ a parent directory for temporary VPrograms.  The
        // VProgram skeleton is bundled with SVAuth.  It doesn't seem there's
        // any benefit to allowing this to be customized? ~ t-mattmc@microsoft.com 2016-06-10
        public string VProgramPath => Path.Combine(SVXFolderPath, "vProgram");

        // cache folder to store existing certification requests
        public string SVXCacheFolderPath => Path.Combine(SVXFolderPath, "cache");
        // a folder to store failed certification requests
        public string SVXCacheFailedCertsFolderPath => Path.Combine(SVXFolderPath, "failed-certs");
        // when saving cache files we will standarlize agentHostname
        // so that the cache files can be shared on multiple machines
        public string canocialagentHostname => "Canonical_RP_Name";

        // If true, keep temporary VPrograms after verification for debugging
        // purposes.
        public bool KeepVPrograms = true;

        public bool ReadableVProgramFolderNames = true;
        
    }
}
