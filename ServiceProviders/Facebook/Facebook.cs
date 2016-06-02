using Microsoft.AspNetCore.Routing;
using System;
using System.Net.Http;

namespace SVAuth.ServiceProviders.Facebook
{
    public class FBAppRegistration
    {
        public string appId;
        public string appSecret;
    }

    class DebugTokenRequest
    {
    }
    public class FBAuthorizationRequest : OAuth20.AuthorizationRequest
    {
        public string type;
    }
    public class FBAuthConclusion : GenericAuth.AuthenticationConclusion
    {
        public string Email;
        public string FullName;
        public string FB_ID;
    }
    public class FBUserProfileResponse : OAuth20.UserProfileResponse
    {
        public string id;
        public string name;
        public string email;
    }
    public class Facebook_RP : OAuth20.Client
    {
        public string UserProfileUrl;
        public Facebook_RP(string client_id1 = null, string return_uri1 = null, string client_secret1 = null, string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null, string UserProfileUrl1 = null)
        : base(client_id1, return_uri1, client_secret1, AuthorizationEndpointUrl1, TokenEndpointUrl1)
        {
            UserProfileUrl = UserProfileUrl1;
        }

        /*** implementing the methods for AuthorizationRequest ***/
        public override OAuth20.AuthorizationRequest createAuthorizationRequest(CST.CST_MSG inputMSG)
        {
            FBAuthorizationRequest _FBAuthorizationRequest = new FBAuthorizationRequest();
            _FBAuthorizationRequest.client_id = client_id;

            _FBAuthorizationRequest.response_type = "code";

            _FBAuthorizationRequest.scope = "user_about_me email";

            _FBAuthorizationRequest.redirect_uri = return_uri;

            _FBAuthorizationRequest.type = "web_server";
            return _FBAuthorizationRequest;
        }
        public override string marshalCreateAuthorizationRequest(OAuth20.AuthorizationRequest _FBAuthorizationRequest)
        {
            return AuthorizationEndpointUrl + "?" + Utils.ObjectToUrlEncodedString(_FBAuthorizationRequest);
        }

        /*** implementing the methods for AccessTokenRequest ***/
        public override OAuth20.AccessTokenRequest createAccessTokenRequest(CST.CST_MSG inputMSG)
        {
            OAuth20.AccessTokenRequest _AccessTokenRequest = new OAuth20.AccessTokenRequest();
            // How does this ever pass verification against the modeled IdP
            // without setting grant_type?? ~ Matt 2016-06-01
            _AccessTokenRequest.client_id = client_id;
            _AccessTokenRequest.code = ((OAuth20.AuthorizationResponse)inputMSG).code;
            _AccessTokenRequest.redirect_uri = return_uri;
            _AccessTokenRequest.client_secret = client_secret;
            return _AccessTokenRequest;
        }

        public override HttpRequestMessage marshalCreateAccessTokenRequest(OAuth20.AccessTokenRequest _AccessTokenRequest)
        {
            // TODO (Matt): Replace with ObjectToForm once we confirm whether
            // the grant_type field should be included?
            var RawRequestUrl = TokenEndpointUrl + "?client_id=" + _AccessTokenRequest.client_id + "&redirect_uri=" + _AccessTokenRequest.redirect_uri
                + "&client_secret=" + _AccessTokenRequest.client_secret + "&code=" + _AccessTokenRequest.code;
            return new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
        }

        /*** implementing the methods for UserProfileRequest ***/
        public override OAuth20.UserProfileRequest createUserProfileRequest(CST.CST_MSG inputMSG)
        {
            OAuth20.UserProfileRequest _UserProfileRequest = new OAuth20.UserProfileRequest();
            _UserProfileRequest.access_token = ((OAuth20.AccessTokenResponse)inputMSG).access_token;
            _UserProfileRequest.fields = "name,email";
            return _UserProfileRequest;
        }

        public override HttpRequestMessage marshalCreateUserProfileRequest(OAuth20.UserProfileRequest _UserProfileRequest)
        {
            var RawRequestUrl = UserProfileUrl + "?" + Utils.ObjectToUrlEncodedString(_UserProfileRequest);
            return new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
        }

        /*** implementing the methods for AuthenticationConclusion ***/
        protected override Type UserProfileResponseType { get { return typeof(FBUserProfileResponse); } }
        public override GenericAuth.AuthenticationConclusion createConclusion(CST.CST_MSG inputMSG)
        {
            var _FBAuthConclusion = new FBAuthConclusion();
            _FBAuthConclusion.UserID = ((FBUserProfileResponse)inputMSG).id;
            _FBAuthConclusion.Email = ((FBUserProfileResponse)inputMSG).email;
            _FBAuthConclusion.FB_ID = ((FBUserProfileResponse)inputMSG).id;
            _FBAuthConclusion.FullName = ((FBUserProfileResponse)inputMSG).name;
            return _FBAuthConclusion;
        }

        public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new Facebook_RP(
                Config.config.AppRegistration.Facebook.appId,
                Config.config.rootUrl + "callback/Facebook",
                Config.config.AppRegistration.Facebook.appSecret,
                "https://www.facebook.com/v2.0/dialog/oauth",
                "https://graph.facebook.com/v2.3/oauth/access_token",
                "https://graph.facebook.com/v2.5/me"
                );
            routeBuilder.MapRoute("login/Facebook", RP.AuthorizationCodeFlow_Login_StartAsync);
            routeBuilder.MapRoute("callback/Facebook", RP.AuthorizationCodeFlow_Login_CallbackAsync);
        }
    }
}
