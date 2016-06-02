using Newtonsoft.Json;

namespace SVAuth.GenericAuth
{
    /***********************************************************/
    /*               Messages between parties                  */
    /***********************************************************/
    public abstract class SignInIdP_Req : SVX.SVX_MSG
    {
        // Ignoring this is right for the one caller so far, in Facebook.  When
        // we have another caller that needs something different, we'll figure
        // out the best design. ~ Matt 2016-06-01
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
        public abstract string UserID { get; }
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

        public SignInIdP_Resp_SignInRP_Req SignInIdP(SignInIdP_Req req) {
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
        // design of the other abstract messages? ~ Matt 2016-06-01
        public string UserID;
    }

    public abstract class RP
    {
        public abstract string Domain { get; set; }
        public abstract string Realm { get; set; }
        public bool AuthenticationDone(AuthenticationConclusion conclusion) {
          //  bool SVX_verified = SVX_Ops.Certify(conclusion);
            /*
            if (CurrentSession["UserID"] != null)
                CurrentSession["UserID"] = SVX_verified ? conclusion.SessionUID : "";
            else
                CurrentSession.Add("UserID", SVX_verified ? conclusion.SessionUID : "");
            return SVX_verified;*/
            return true;
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

        // TODO (Matt): Rename to NecessaryCondition1.
        public static void BadPersonCannotSignInAsGoodPerson(AuthenticationConclusion conclusion) {
            ID_Claim ID_claim = AS.IdentityRecords.getEntry(
                                        SignInIdP_Req.IdPSessionSecret,
                                        RP.Realm);
           // Contract.Assert(ID_claim.Redir_dest == this.RP.Domain && ID_claim.UserID == conclusion.SessionUID);
        }
    }
}
