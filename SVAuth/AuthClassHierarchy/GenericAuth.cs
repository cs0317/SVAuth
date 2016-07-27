using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System;
using System.Diagnostics.Contracts;
using System.Threading.Tasks;

// Keep a namespace structure mirroring the TypeScript external modules, for the moment.
// ~ t-mattmc@microsoft.com 2016-05-31
namespace SVAuth.GenericAuth
{
#if false
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
#endif

    static class GenericAuthStandards
    {
        // We need this several places (model IdPs and secret generators that
        // the vProgram instantiates independently), so see how long we can get
        // away with just standardizing it rather than finding a way to call the
        // correct implementation in each place.
        public static SVX.Principal GetIdPUserPrincipal(SVX.Principal idpPrincipal, string userID) =>
            SVX.Principal.Of(idpPrincipal.name + ":" + userID);

        // We might be able to make this more precise by taking the host name,
        // but I don't want to deal with making that analyzable in the vProgram
        // right now.
        public static SVX.Principal GetUrlTargetPrincipal(string url) =>
            SVX.Principal.Of("url_target:" + url);
    }

    /***********************************************************/
    /*                          Parties                        */
    /***********************************************************/
    /*         AS stands for Authority Server                  */
    /*         AS is both IdP and Authorization Server         */
    /***********************************************************/

    public abstract class AS : SVX.Participant
    {
        public AS(SVX.Principal asPrincipal) : base(asPrincipal) { }

        // A few definitions that are needed by the RP.  Wait and see if we need
        // to make them virtual.

        protected SVX.DeclarablePredicate<SVX.Principal /*underlying client*/, string /*username*/> SignedInPredicate
            = new SVX.DeclarablePredicate<SVX.Principal, string>();

        public bool Ghost_CheckSignedIn(SVX.Principal underlyingPrincipal, string userID) =>
            SignedInPredicate.Check(underlyingPrincipal, userID);

#if false
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
#endif
    }

    public class UserProfile
    {
        // Should this rather be an abstract property for consistency with the
        // design of the other abstract messages? ~ t-mattmc@microsoft.com 2016-06-01
        public string UserID;
    }

    public class AuthenticationConclusion : SVX.SVX_MSG
    {
        public SVX.PrincipalHandle authenticatedClient;

        // Putting the user profile in its own class was the easiest way to
        // avoid sending authenticatedClient to the platform adapter and seems
        // to be a sensible thing to do in its own right.
        public UserProfile userProfile;
    }

    public abstract class RP : SVX.Participant
    {
        public RP(SVX.Principal rpPrincipal) : base(rpPrincipal) { }

        // idpParticipantId.type should extend AS.
        protected abstract SVX.ParticipantId idpParticipantId { get; }

        // Set this if you want to test the protocol before you have the
        // verification working.
        protected bool BypassCertification = false;

#if false
        public abstract string Domain { get; set; }
        public abstract string Realm { get; set; }
#endif
        public async Task AuthenticationDone(AuthenticationConclusion conclusion, SVAuthRequestContext context)
        {
            if (context.client != conclusion.authenticatedClient)
                throw new Exception("Attempt to apply an AuthenticationConclusion to the wrong session.");

            if (!BypassCertification)
            {
                SVX.SVX_Ops.Certify(conclusion, LoginSafety, idpParticipantId);
                SVX.SVX_Ops.Certify(conclusion, LoginXSRFPrevention, idpParticipantId);
            }
            await Utils.AbandonAndCreateSessionAsync(conclusion, context);
        }

        public bool LoginSafety(AuthenticationConclusion conc)
        {
            var idp = (AS)SVX.VProgram_API.GetParticipant(idpParticipantId);
            var idpUserPrincipal = GenericAuthStandards.GetIdPUserPrincipal(idp.SVX_Principal, conc.userProfile.UserID);
            SVX.VProgram_API.AssumeTrustedServer(idp.SVX_Principal);
            SVX.VProgram_API.AssumeTrustedServer(SVX_Principal);
            SVX.VProgram_API.AssumeTrusted(idpUserPrincipal);

            return SVX.VProgram_API.ActsFor(conc.authenticatedClient, idpUserPrincipal);
        }

        public bool LoginXSRFPrevention(AuthenticationConclusion conc)
        {
            var idp = (AS)SVX.VProgram_API.GetParticipant(idpParticipantId);
            SVX.VProgram_API.AssumeTrustedServer(idp.SVX_Principal);
            SVX.VProgram_API.AssumeTrustedServer(SVX_Principal);
            SVX.VProgram_API.AssumeTrustedBrowser(conc.authenticatedClient);

            return idp.Ghost_CheckSignedIn(SVX.VProgram_API.UnderlyingPrincipal(conc.authenticatedClient), conc.userProfile.UserID);
        }
    }

#if false
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

    public interface Nondet_Base
    {
        int Int();
        string String();
        bool Bool();
        SVX.SVX_MSG SVX_MSG();
    }
#endif
}
