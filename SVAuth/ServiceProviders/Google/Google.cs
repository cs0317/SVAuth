using Microsoft.AspNetCore.Routing;
using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using BytecodeTranslator.Diagnostics;
using Newtonsoft.Json.Linq;
using System.Threading.Tasks;

namespace SVAuth.ServiceProviders.Google
{
    public class GGAppRegistration
    {
        public string clientID;
        public string clientSecret;
    }
    public class GGAuthenticationRequest : OIDC10.AuthenticationRequest
    {
    }
    public class JwtToken: OIDC10.JwtToken
    {
        public string name, email, email_verified;
    }
    public class GGAuthConclusion : GenericAuth.AuthenticationConclusion
    {
        public string Email;
        public string FullName;
        public string GG_ID;
    }
    public class Google_RP: OIDC10.RelyingParty
    {
        public string UserProfileUrl,SignatureValidationUrl;
        public Google_RP(string client_id1, string return_uri1, string client_secret1, string AuthorizationEndpointUrl1, string UserProfileUrl1, string SignatureValidationUrl1)
        : base(client_id1, return_uri1, client_secret1, AuthorizationEndpointUrl1, null)
        {
            UserProfileUrl = UserProfileUrl1;
            SignatureValidationUrl = SignatureValidationUrl1;
        }
        public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new Google_RP(
                Config.config.AppRegistration.Google.clientID,
                Config.config.rootUrl + "callback/Google",
                Config.config.AppRegistration.Google.clientSecret,
                "https://accounts.google.com/o/oauth2/auth",
                "https://www.googleapis.com/oauth2/v2/userinfo",
                "https://www.googleapis.com/oauth2/v3/tokeninfo"
                );
            routeBuilder.MapRoute("login/Google", RP.Login_StartAsync);
            routeBuilder.MapRoute("callback/Google", RP.ImplicitFlow_Login_CallbackAsync);
        }
        public override OAuth20.AuthorizationRequest createAuthorizationRequest(SVX.SVX_MSG inputMSG)
        {
            GGAuthenticationRequest GGAuthenticationRequest = new GGAuthenticationRequest();
            GGAuthenticationRequest.client_id = client_id;
            GGAuthenticationRequest.response_type = "id_token token";
            GGAuthenticationRequest.scope = "openid email profile";
            GGAuthenticationRequest.redirect_uri = redirect_uri;
            GGAuthenticationRequest.response_mode = "form_post";
            return GGAuthenticationRequest;
        }
        public override string marshalCreateAuthorizationRequest(OAuth20.AuthorizationRequest MSAuthenticationRequest)
        {
            return AuthorizationEndpointUrl + "?" + Utils.ObjectToUrlEncodedString(MSAuthenticationRequest);
        }

        protected override void set_parse_id_token(SVX.SVX_MSG msg, JObject id_token)
        {
           ((OIDC10.AuthenticationResponse_with_id_token)msg).parsed_id_token = Utils.UnreflectObject<JwtToken>(id_token);
        }
        public override bool verify_and_decode_ID_Token(OIDC10.AuthenticationResponse_with_id_token AuthenticationResponse)
        {
            var RawRequestUrl = SignatureValidationUrl + "?id_token=" + AuthenticationResponse.id_token.ToString();
            var rawReq = new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
            var RawResponse = SVX.Utils.PerformHttpRequestAsync(rawReq).Result;
            if (RawResponse.StatusCode != System.Net.HttpStatusCode.OK)
                return false;
            set_parse_id_token(AuthenticationResponse, JObject.Parse(RawResponse.Content.ReadAsStringAsync().Result));
            return true;
        }
        protected  string getFullName(string access_token)
        {           
            var RawRequestUrl = UserProfileUrl + "?access_token=" + access_token;
            var rawReq= new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
            var RawResponse = SVX.Utils.PerformHttpRequestAsync(rawReq).Result;
            return (string)(JObject.Parse(RawResponse.Content.ReadAsStringAsync().Result)["name"]);
        }
        /*** implementing the methods for AuthenticationConclusion ***/
        public override GenericAuth.AuthenticationConclusion createConclusion(SVX.SVX_MSG inputMSG)
        {
            //recordMe(...)

             var AuthConclusion = new GGAuthConclusion();
             OIDC10.JwtToken jwtToken = ((OIDC10.AuthenticationResponse_with_id_token)inputMSG).parsed_id_token;
             if (jwtToken.aud != this.client_id)
                return null;
             AuthConclusion.UserID = ((JwtToken)jwtToken).email;
             AuthConclusion.Email = ((JwtToken)jwtToken).email;
             AuthConclusion.GG_ID = ((JwtToken)jwtToken).sub;
             AuthConclusion.FullName = getFullName(((OIDC10.AuthenticationResponse_with_id_token)inputMSG).access_token);
             return AuthConclusion;
        }
        protected override string VProgramMainContent => null;
        protected override Type ModelAuthorizationServerType => typeof(OAuth20.AuthorizationServer);
    }
}


