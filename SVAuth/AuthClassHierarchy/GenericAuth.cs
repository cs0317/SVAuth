using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System;
using System.Diagnostics.Contracts;
using System.Threading.Tasks;

// Keep a namespace structure mirroring the TypeScript external modules, for the moment.
// ~ t-mattmc@microsoft.com 2016-05-31
namespace SVAuth.GenericAuth
{
    /***********************************************************/
    /*               Messages between parties                  */
    /***********************************************************/
    public abstract class SignInIdP_Req : SVX.SVX_MSG
    {
        // Ignoring this is right for the one caller so far, in Facebook.  When
        // we have another caller that needs something different, we'll figure
        // out the best design. ~ t-mattmc@microsoft.com 2016-06-01
        [JsonIgnore]
        public string IdPSessionSecret;
        // Serialize the concrete properties instead.
        [JsonIgnore]
        public abstract string Realm { get; set; }
    }

    public abstract class SignInIdP_Resp_SignInRP_Req : SVX.SVX_MSG
    {
    }

    public abstract class SignInRP_Resp : SVX.SVX_MSG
    {
    }

    /***********************************************************/
    /*               Data structures on parties                */
    /***********************************************************/

    public abstract class ID_Claim
    {
        public abstract string GetUserID(string UserID_Field_Name);
        public abstract string Redir_dest { get; }
    }

    public interface IdPAuthRecords_Base
    {
        ID_Claim getEntry(string IdPSessionSecret, string Realm);
        bool setEntry(string IdPSessionSecret, string Realm, ID_Claim _ID_Claim);
    }

    /***********************************************************/
    /*                          Parties                        */
    /***********************************************************/
    /*         AS stands for Authority Server                  */
    /*         AS is both IdP and Authorization Server         */
    /***********************************************************/

    public abstract class AS
    {
        public IdPAuthRecords_Base IdentityRecords;

        public SignInIdP_Resp_SignInRP_Req SignInIdP(SignInIdP_Req req)
        {
            GlobalObjects_base.SignInIdP_Req = req;

            if (req == null) return null;
            ID_Claim _ID_Claim = Process_SignInIdP_req(req);
            if (IdentityRecords.setEntry(req.IdPSessionSecret, req.Realm, _ID_Claim) == false)
                return null;
            return Redir(_ID_Claim.Redir_dest, _ID_Claim);
        }

        public abstract ID_Claim Process_SignInIdP_req(SignInIdP_Req req);
        public abstract SignInIdP_Resp_SignInRP_Req Redir(string dest, ID_Claim _ID_Claim);
    }

    public class AuthenticationConclusion : SVX.SVX_MSG
    {
        // Should this rather be an abstract property for consistency with the
        // design of the other abstract messages? ~ t-mattmc@microsoft.com 2016-06-01
        public string UserID;
    }

    public abstract class RP
    {
        public abstract string Domain { get; set; }
        public abstract string Realm { get; set; }
        public void VerifyAuthentication(AuthenticationConclusion conclusion)
        {
            GlobalObjects_base.BadPersonCannotSignInAsGoodPerson(conclusion);
        }
        public async Task AuthenticationDone(AuthenticationConclusion conclusion, HttpContext context)
        {
            /* Compared to the original AuthPlatelet, I'm choosing to record a
             * separate SVX method right here for the certification.  Otherwise,
             * it would be easy for a new protocol class (like OAuth20) to
             * accidentally do the certification outside the last SVX method so
             * that the vProgram doesn't include the verification, which would
             * completely nullify SVX in a way that's hard to notice.  Of
             * course, we have more to do to try to prevent other similarly
             * devastating mistakes in setting up SVX.
             * ~ t-mattmc@microsoft.com 2016-06-07
             */
            var verifiedMsg = new SVX.SVX_MSG();
            SVX.SVX_Ops.recordCustom(this, conclusion, verifiedMsg, nameof(VerifyAuthentication),
                SVX.SVXSettings.settings.MyPartyName, false, false);
            if (!SVX.SVX_Ops.Certify(verifiedMsg))
            {
                throw new Exception("SVX certification failed.");
            }
            await Utils.AbandonAndCreateSessionAsync(conclusion, context);
        }
    }


    /****************************************************************/
    /* The definition of the "Authentication/Authorization" problem */
    /****************************************************************/
    public class GlobalObjects_base
    {
        public static SignInIdP_Req SignInIdP_Req;
        public static AS AS;
        public static RP RP;

        // TODO (t-mattmc@microsoft.com): Rename to NecessaryCondition1.
        public static void BadPersonCannotSignInAsGoodPerson(AuthenticationConclusion conclusion)
        {
            ID_Claim ID_claim = AS.IdentityRecords.getEntry(
                                        SignInIdP_Req.IdPSessionSecret,
                                        RP.Realm);
            Contract.Assert(ID_claim.Redir_dest == RP.Domain && ID_claim.GetUserID("email") == conclusion.UserID);
        }
    }

    // Currently unused due to BCT workaround on OAuth20.NondetOAuth20.
    // ~ Matt 2016-06-15
#if false
    public interface Nondet_Base
    {
        int Int();
        string String();
        bool Bool();
        SVX.SVX_MSG SVX_MSG();
    }
#endif
}
