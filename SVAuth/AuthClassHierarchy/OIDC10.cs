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
using SVAuth.OAuth20;

namespace SVAuth.OIDC10
{

    /***********************************************************/
    /*               Messages between parties                  */
    /***********************************************************/

    public class AuthenticationRequest : OAuth20.AuthorizationRequest
    {
        public string response_mode = null;
        public string nonce = null;
        public string display = null;
        public string prompt = null;
        public string max_age = null;
        public string ui_locales = null;
        public string id_token_hint = null;
        public string login_hint = null;
        public string acr_values = null;
    }

    public class AuthenticationResponse_with_id_token : OAuth20.AuthorizationResponse
    {
        public string id_token, access_token;
        public JwtToken parsed_id_token;
    }

    public class JwtToken 
    {
        public string aud, iss, exp, sub;
    }
    public class TokenResponse : OAuth20.AccessTokenResponse
    {
        public string id_token;
        public JwtToken parsed_id_token;
    }

    public abstract class RelyingParty : OAuth20.Client
    {
        public RelyingParty(SVX.Principal rpPrincipal, string client_id1, string redierct_uri1, string client_secret1, string AuthorizationEndpointUrl1, string TokenEndpointUrl1)
            : base(rpPrincipal)
        {
            client_id = client_id1;
            redirect_uri = redierct_uri1;
            client_secret = client_secret1;
            AuthorizationEndpointUrl = AuthorizationEndpointUrl1;
            TokenEndpointUrl = TokenEndpointUrl1;
        }

        protected override ModelAuthorizationServer CreateModelAuthorizationServer()
        {
            // SVX verification is not implemented yet.
            throw new NotImplementedException();
        }

        protected abstract void set_parse_id_token(SVX.SVX_MSG msg, JObject id_token);
        // Use a different name: SVX is not guaranteed to handle method overloading.
        public virtual GenericAuth.AuthenticationConclusion createConclusionOidc(
            AuthorizationResponse authenticationResponse, TokenResponse tokenResponse) { return null; }
        public override async Task AuthorizationCodeFlow_Login_CallbackAsync(HttpContext httpContext)
        {
            Trace.Write("AuthorizationCodeFlow_Login_CallbackAsync");
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);

            var authenticationResponse = (OAuth20.AuthorizationResponse)Utils.ObjectFromFormPost(
                context.http.Request.Form, LoginCallbackRequestType);
            // Just enough for createConclusionOidc until we do a real SVX import.
            authenticationResponse.SVX_sender = context.client;
            var _AccessTokenRequest = createAccessTokenRequest(authenticationResponse);
            // OAuth20 defines "code" as a secret, but OIDC10 isn't using SVX
            // yet.  This seems to be the least bad workaround.
            _AccessTokenRequest.code.BypassExportCheck();
            var rawReq = marshalAccessTokenRequest(_AccessTokenRequest);
            var RawAccessTokenResponse = await Utils.PerformHttpRequestAsync(rawReq);
            Trace.Write("Got AccessTokenResponse");

            JObject jObject = JObject.Parse(RawAccessTokenResponse.Content.ReadAsStringAsync().Result);
            TokenResponse tokenResponse = Utils.UnreflectObject<TokenResponse>(jObject);
            JObject id_token = JObject.Parse(JwtCore.JsonWebToken.Decode(tokenResponse.id_token.ToString(), "", false));
            set_parse_id_token(tokenResponse, id_token);
            var conclusion = createConclusionOidc(authenticationResponse, tokenResponse);
            await AuthenticationDone(conclusion, context);
        }
        public virtual bool verify_and_decode_ID_Token(AuthenticationResponse_with_id_token AuthenticationResponse) { return false; }
        public virtual GenericAuth.AuthenticationConclusion createConclusionOidcImplicit(
            AuthenticationResponse_with_id_token authenticationResponse) { return null; }
        public async Task ImplicitFlow_Login_CallbackAsync(HttpContext httpContext)
        {
            Trace.Write("ImplicitFlow_Login_CallbackAsync");
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);
            AuthenticationResponse_with_id_token inputMSG = (AuthenticationResponse_with_id_token)Utils.ObjectFromFormPost
                (context.http.Request.Form, typeof(AuthenticationResponse_with_id_token));
            // Just enough for createConclusionOidcImplicit until we do a real SVX import.
            inputMSG.SVX_sender = context.client;
            if (!verify_and_decode_ID_Token(inputMSG))
            {
                context.http.Response.Redirect(context.http.Request.Cookies["LoginPageUrl"]);
                return;
            }
            Trace.Write("Got Valid AuthenticationResponse");

            GenericAuth.AuthenticationConclusion conclusion = createConclusionOidcImplicit(inputMSG);
            if (conclusion == null)
            {
                context.http.Response.Redirect(context.http.Request.Cookies["LoginPageUrl"]);
                return;
            }

            await AuthenticationDone(conclusion, context);
        }
    }
}
