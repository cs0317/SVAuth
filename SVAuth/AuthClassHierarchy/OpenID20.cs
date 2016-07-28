using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Reflection;
using JwtCore;

namespace SVAuth.OpenID20
{

    /***********************************************************/
    /*               Messages between parties                  */
    /***********************************************************/

    public class AuthenticationRequest : SVX.SVX_MSG
    {
        [JsonProperty("openid.ns")]
        public string openid__ns = "http://specs.openid.net/auth/2.0";
        [JsonProperty("openid.mode")]
        public string openid__mode;
        [JsonProperty("openid.claimed_id")]
        public string openid__claimed_id;
        [JsonProperty("openid.identity")]
        public string openid__identity;
        [JsonProperty("openid.assoc_handle")]
        public string openid__assoc_handle;
        [JsonProperty("openid.return_to")]
        public string openid__return_to;
        [JsonProperty("openid.realm")]
        public string openid__realm;
      /*  [JsonProperty("openid.sreg.required")]
        public string openid__sreg__required;
        [JsonProperty("openid.sreg.policy_url")]
        public string openid__sreg__policy_url; */
    }

    public class AuthenticationResponse : SVX.SVX_MSG  /* a.k.a. PositiveAssertion in the OpenID 2.0 spec */
    {
        [JsonProperty("openid.ns")]
        public string openid__ns = "http://specs.openid.net/auth/2.0";
        [JsonProperty("openid.mode")]
        public string openid__mode = "id_res";
        [JsonProperty("openid.op_endpoint")]
        public string openid__op_endpoint;
        [JsonProperty("openid.claimed_id")]
        public string openid__claimed_id;
        [JsonProperty("openid.identity")]
        public string openid__identity;
        [JsonProperty("openid.return_to")]
        public string openid__return_to;
        [JsonProperty("openid.response_nonce")]
        public string openid__response_nonce;
        [JsonProperty("openid.assoc_handle")]
        public string openid__assoc_handle;
        [JsonProperty("openid.invalidate_handle")]
        public string openid__invalidate_handle;
        [JsonProperty("openid.signed")]
        public string openid__signed;
        [JsonProperty("openid.sig")]
        public string openid__sig;
    }

   public abstract class RelyingParty : GenericAuth.RP
    {
        public string realm;
        public string IdP_OpenID20_Uri;
        public string return_to_uri;
        public RelyingParty(SVX.Principal rpPrincipal, string IdP_OpenID20_Uri1, string return_to_uri1)
            : base(rpPrincipal)
        {
            Uri uri = new Uri(return_to_uri1);
            realm = uri.Host;
            return_to_uri = return_to_uri1;
            IdP_OpenID20_Uri = IdP_OpenID20_Uri1;
        }

        protected override SVX.ParticipantId idpParticipantId
        {
            // SVX verification is not implemented yet.
            get { throw new NotImplementedException(); }
        }

        public abstract AuthenticationRequest createAuthenticationRequest(SVX.PrincipalFacet client);
        public abstract string /*Uri*/ marshalAuthenticationRequest(AuthenticationRequest _AuthorizationRequest);
        public Task Login_StartAsync(HttpContext httpContext)
        {
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);

            var _AuthenticationRequest = createAuthenticationRequest(context.client);
            var rawReq = marshalAuthenticationRequest(_AuthenticationRequest);
            context.http.Response.Redirect(rawReq);

            return Task.CompletedTask;
        }
        public abstract AuthenticationResponse verify_and_parse_AuthenticationResponse(HttpContext context);
        public abstract GenericAuth.AuthenticationConclusion createConclusion(AuthenticationResponse inputMSG);
        public async Task Login_CallbackAsync(HttpContext httpContext)
        {
            Trace.Write("Login_CallbackAsync");
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);
            AuthenticationResponse inputMSG = verify_and_parse_AuthenticationResponse(context.http);
            // Just enough for createConclusion until we do a real SVX import.
            inputMSG.SVX_sender = context.client;

            if (inputMSG==null)
            {
                context.http.Response.Redirect(context.http.Request.Cookies["LoginPageUrl"]);
                return;
            }
            Trace.Write("Got Valid AuthenticationResponse");

            GenericAuth.AuthenticationConclusion conclusion = createConclusion(inputMSG);
            if (conclusion == null)
            {
                context.http.Response.Redirect(context.http.Request.Cookies["LoginPageUrl"]);
                return;
            }

            await AuthenticationDone(conclusion, context);
        }
    }
}
