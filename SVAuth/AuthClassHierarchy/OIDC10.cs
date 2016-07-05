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

    public class AuthenticationResponse : OAuth20.AuthorizationResponse
    {
    }
    public class AuthenticationResponse_with_id_token : OAuth20.AuthorizationResponse
    {
        public string id_token, access_token;
        public JwtToken parsed_id_token;
    }

    public class TokenRequest : OAuth20.AccessTokenRequest
    {
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
        public RelyingParty(string client_id1, string redierct_uri1, string client_secret1, string AuthorizationEndpointUrl1, string TokenEndpointUrl1)
        {
            client_id = client_id1;
            redirect_uri = redierct_uri1;
            client_secret = client_secret1;
            AuthorizationEndpointUrl = AuthorizationEndpointUrl1;
            TokenEndpointUrl = TokenEndpointUrl1;
        }
        protected abstract void set_parse_id_token(SVX.SVX_MSG msg, JObject id_token);
        public override async Task AuthorizationCodeFlow_Login_CallbackAsync(HttpContext context)
        {
            Trace.Write("AuthorizationCodeFlow_Login_CallbackAsync");

            SVX.SVX_MSG inputMSG = (SVX.SVX_MSG)Utils.ObjectFromFormPost(
                context.Request.Form, LoginCallbackRequestType);
           // SVX.SVX_Ops.recordCustom(new DummyConcreteAuthorizationServer(), _UserProfileRequest, inputMSG3,
           //    nameof(DummyConcreteAuthorizationServer.DummyGetUserProfile), "AS", false, false);
            var _AccessTokenRequest = _createAccessTokenRequest(inputMSG);
            var rawReq = marshalCreateAccessTokenRequest(_AccessTokenRequest);
            var RawAccessTokenResponse = await SVX.Utils.PerformHttpRequestAsync(rawReq);
            Trace.Write("Got AccessTokenResponse");

            JObject jObject = JObject.Parse(RawAccessTokenResponse.Content.ReadAsStringAsync().Result);
            TokenResponse inputMSG2 = Utils.UnreflectObject<TokenResponse>(jObject);
            JObject id_token = JObject.Parse(JwtCore.JsonWebToken.Decode(inputMSG2.id_token.ToString(), "", false));
            set_parse_id_token(inputMSG2, id_token);
            var conclusion = _createConclusion(inputMSG2);
            await AuthenticationDone(conclusion, context);
        }
        public virtual bool verify_and_decode_ID_Token(AuthenticationResponse_with_id_token AuthenticationResponse) { return false; }
        public async Task ImplicitFlow_Login_CallbackAsync(HttpContext context)
        {
            Trace.Write("ImplicitFlow_Login_CallbackAsync");
            AuthenticationResponse_with_id_token inputMSG = (AuthenticationResponse_with_id_token)Utils.ObjectFromFormPost
                (context.Request.Form, typeof(AuthenticationResponse_with_id_token));
            if (!verify_and_decode_ID_Token(inputMSG))
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
