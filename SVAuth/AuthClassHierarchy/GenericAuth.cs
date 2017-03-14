using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System;
using System.Diagnostics.Contracts;
using System.Threading.Tasks;

// Keep a namespace structure mirroring the TypeScript external modules, for the moment.
// ~ t-mattmc@microsoft.com 2016-05-31
namespace SVAuth.GenericAuth
{

    static class GenericAuthStandards
    {
        // We need this several places (model IdPs and secret generators that
        // the vProgram instantiates independently), so see how long we can get
        // away with just standardizing it rather than finding a way to call the
        // correct implementation in each place.
        public static SVX.Entity GetIdPUserPrincipal(SVX.Entity idpPrincipal, string userID) =>
            SVX.Entity.Of(idpPrincipal.name + ":" + userID);

        // We might be able to make this more precise by taking the host name,
        // but I don't want to deal with making that analyzable in the vProgram
        // right now.
        public static SVX.Entity GetUrlTargetPrincipal(string url) =>
            SVX.Entity.Of("url_target:" + url);
    }

    /***********************************************************/
    /*                          Parties                        */
    /***********************************************************/
    /*         AS stands for Authority Server                  */
    /*         AS is both IdP and Authorization Server         */
    /***********************************************************/

    public abstract class AS : SVX.Participant
    {
        public AS(SVX.Entity asPrincipal) : base(asPrincipal) { }

        // A few definitions that are needed by the RP.  Wait and see if we need
        // to make them virtual.

        protected SVX.DeclarablePredicate<SVX.Entity /*underlying client*/, string /*username*/> BrowserOwnedBy
            = new SVX.DeclarablePredicate<SVX.Entity, string>();

        public bool Ghost_CheckSignedIn(SVX.Entity browser, string userID) =>
            BrowserOwnedBy.Check(browser, userID);

    }

    public class UserProfile
    {
        // Should this rather be an abstract property for consistency with the
        // design of the other abstract messages? ~ t-mattmc@microsoft.com 2016-06-01
        public string UserID;
    }

    public class AuthenticationConclusion : SVX.SVX_MSG
    {
        public SVX.Principal channel;

        // Putting the user profile in its own class was the easiest way to
        // avoid sending authenticatedClient to the platform adapter and seems
        // to be a sensible thing to do in its own right.
        public UserProfile userProfile;
    }

    public abstract class RP : SVX.Participant
    {
        public RP(SVX.Entity rpPrincipal) : base(rpPrincipal) { }

        // idpParticipantId.type should extend AS.
        protected abstract SVX.ParticipantId idpParticipantId { get; }

        // Set this if you want to test the protocol before you have the
        // verification working.
        protected bool BypassCertification = false;

        public async Task AuthenticationDone(AuthenticationConclusion conclusion, SVAuthRequestContext context)
        {
            if (context.channel != conclusion.channel)
                throw new Exception("Attempt to apply an AuthenticationConclusion to the wrong channel.");

            if (!BypassCertification)
            {
               SVX.SVX_Ops.Certify(conclusion, LoginSafety, idpParticipantId);
               SVX.SVX_Ops.Certify(conclusion, LoginIntent, idpParticipantId);
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
           // bool x = SVX.VProgram_API.ActsFor(conc.authenticatedClient, idp.SVX_Principal);
           // bool y = SVX.VProgram_API.ActsFor(conc.authenticatedClient, SVX_Principal);
            return SVX.VProgram_API.ActsFor(conc.channel, idpUserPrincipal);
        }

        public bool LoginIntent(AuthenticationConclusion conc)
        {
            var idp = (AS)SVX.VProgram_API.GetParticipant(idpParticipantId);
            SVX.VProgram_API.AssumeTrustedServer(idp.SVX_Principal);
            SVX.VProgram_API.AssumeTrustedServer(SVX_Principal);
            SVX.VProgram_API.AssumeTrustedBrowser(conc.channel);

            return idp.Ghost_CheckSignedIn(SVX.VProgram_API.Owner(conc.channel), conc.userProfile.UserID);
        }
    }

}
