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

    public class AuthenticationRequest : GenericAuth.SignInIdP_Req
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
        public override string Realm
        {
            get { return openid__realm; }
            set { openid__realm = value; }
        }
    }

    public class AuthenticationResponse  /* a.k.a. PositiveAssertion in the OpenID 2.0 spec */: GenericAuth.SignInIdP_Resp_SignInRP_Req
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
        public RelyingParty(string IdP_OpenID20_Uri1, string return_to_uri1)
        {
            Uri uri = new Uri(return_to_uri1);
            realm = uri.Host;
            return_to_uri = return_to_uri1;
            IdP_OpenID20_Uri = IdP_OpenID20_Uri1;
        }
        public override string Realm
        {
            get { return realm; }
            set { realm = value; }
        }

        public override string Domain
        {
            get { return realm; }
            set { realm = value; }
        }

        public abstract AuthenticationRequest createAuthenticationRequest(SVX.SVX_MSG inputMSG);
        public AuthenticationRequest _createAuthenticationRequest(SVX.SVX_MSG inputMSG)
        {
            var outputMSG = createAuthenticationRequest(inputMSG);
            SVX.SVX_Ops.recordme(this, inputMSG, outputMSG);
            return outputMSG;
        }
        public abstract string /*Uri*/ marshalAuthenticationRequest(AuthenticationRequest _AuthorizationRequest);
        public Task Login_StartAsync(HttpContext context)
        {
            SVX.SVX_MSG inputMSG = new SVX.SVX_MSG();
            var _AuthenticationRequest = _createAuthenticationRequest(inputMSG);
            var rawReq = marshalAuthenticationRequest(_AuthenticationRequest);
            context.Response.Redirect(rawReq);

            return Task.CompletedTask;
        }
        public abstract AuthenticationResponse verify_and_parse_AuthenticationResponse(HttpContext context);
        public abstract GenericAuth.AuthenticationConclusion createConclusion(AuthenticationResponse inputMSG);
        public GenericAuth.AuthenticationConclusion _createConclusion(AuthenticationResponse inputMSG)
        {
            var outputMSG = this.createConclusion(inputMSG);
            SVX.SVX_Ops.recordme(this, inputMSG, outputMSG, true, true);
            return outputMSG;
        }
        public async Task Login_CallbackAsync(HttpContext context)
        {

            Trace.Write("Login_CallbackAsync");
            AuthenticationResponse inputMSG = verify_and_parse_AuthenticationResponse(context);

            if (inputMSG==null)
            {
                context.Response.Redirect(context.Request.Cookies["LoginPageUrl"]);
                return;
            }
            Trace.Write("Got Valid AuthenticationResponse");

            GenericAuth.AuthenticationConclusion conclusion = _createConclusion(inputMSG);
            if (conclusion == null)
            {
                context.Response.Redirect(context.Request.Cookies["LoginPageUrl"]);
                return;
            }

            await AuthenticationDone(conclusion, context);
        }
    }
}
