using Microsoft.AspNetCore.Routing;
using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using BytecodeTranslator.Diagnostics;
using System.IO;

namespace SVAuth.ServiceProviders.Weibo
{
    public class WBAppRegistration
    {
        public string clientID;
        public string clientSecret;
    }

    class DebugTokenRequest
    {
    }
    public class WBAccessTokenResponse : OAuth20.AccessTokenResponse
    {
        public string uid;
    }
    public class WBUserProfile : GenericAuth.UserProfile
    {
        public string Email;
        public string FullName;
    }
    public class WBUserProfileRequest : OAuth20.UserProfileRequest
    {
        public string uid;
    }
    
    public class WBUserProfileResponse : OAuth20.UserProfileResponse
    {
        public string id;
        public string name;
    }

    public class Weibo_RP : OAuth20.Client
    {
        public string UserProfileUrl;
        public Weibo_RP(SVX.Entity rpPrincipal,
            string client_id1 = null, string redierct_uri1 = null, string client_secret1 = null,
            string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null, string UserProfileUrl1 = null,
            string stateKey = null)
        : base(rpPrincipal, client_id1, redierct_uri1, client_secret1, AuthorizationEndpointUrl1, TokenEndpointUrl1, stateKey)
        {
            UserProfileUrl = UserProfileUrl1;
        }
        protected override Type AccessTokenResponseType { get { return typeof(WBAccessTokenResponse); } }
        protected override OAuth20.ModelAuthorizationServer CreateModelAuthorizationServer() =>
            new Weibo_IdP(Weibo_IdP.facebookPrincipal);

        // Very little of this is Weibo-specific.  Consider moving it to
        // OAuth20.  (Exception: it's unclear if the user profile request is an
        // OAuth20 concept at all, so maybe the entirety of that should move to
        // Weibo with only a hook remaining in OAuth20.)

        /*** implementing the methods for AuthorizationRequest ***/
        public override OAuth20.AuthorizationRequest createAuthorizationRequest(SVX.Channel client)
        {
            var authorizationRequest = new OAuth20.AuthorizationRequest();
            authorizationRequest.client_id = client_id;      
            authorizationRequest.response_type = "code";
            //authorizationRequest.scope = "user_about_me email";
            authorizationRequest.redirect_uri = redirect_uri;
            var stateParams = new OAuth20.StateParams
            {
                client = client,
                idpPrincipal = idpParticipantId.principal
            };
            authorizationRequest.state = stateGenerator.Generate(stateParams, SVX_Principal);
            return authorizationRequest;
        }
        public override string marshalAuthorizationRequest(OAuth20.AuthorizationRequest authorizationRequest)
        {
            string req = AuthorizationEndpointUrl + "?" + Utils.ObjectToUrlEncodedString(authorizationRequest);
            //The next line is needed because Weibo app registration doesn't allow the hostname to be localhost, but 127.0.0.1
            req = req.Replace("%2F%2Flocalhost", "%2F%2F127.0.0.1");
            return req;
        }

        /*** implementing the methods for AccessTokenRequest ***/
        public override OAuth20.AccessTokenRequest createAccessTokenRequest(OAuth20.AuthorizationResponse authorizationResponse)
        {
            var stateParams = new OAuth20.StateParams
            {
                client = authorizationResponse.SVX_sender,
                idpPrincipal = idpParticipantId.principal
            };
            stateGenerator.Verify(stateParams, authorizationResponse.state);

            OAuth20.AccessTokenRequest _AccessTokenRequest = new OAuth20.AccessTokenRequest();
            _AccessTokenRequest.client_id = client_id;
            _AccessTokenRequest.code = authorizationResponse.code;
            _AccessTokenRequest.redirect_uri = redirect_uri;
            _AccessTokenRequest.grant_type = "authorization_code";
            _AccessTokenRequest.client_secret = client_secret;
            return _AccessTokenRequest;
        }

        public override HttpRequestMessage marshalAccessTokenRequest(OAuth20.AccessTokenRequest accessTokenRequest)
        {            
            var RawRequestUrl = TokenEndpointUrl + "?" + Utils.ObjectToUrlEncodedString(accessTokenRequest);
            RawRequestUrl = RawRequestUrl.Replace("%2F%2Flocalhost", "%2F%2F127.0.0.1");
            return new HttpRequestMessage(HttpMethod.Post, RawRequestUrl);
        }

        /*** implementing the methods for UserProfileRequest ***/
        public override OAuth20.UserProfileRequest createUserProfileRequest(OAuth20.AccessTokenResponse accessTokenResponse)
        {
            WBUserProfileRequest userProfileRequest = new WBUserProfileRequest();
            userProfileRequest.access_token = accessTokenResponse.access_token;
            userProfileRequest.uid = ((WBAccessTokenResponse)accessTokenResponse).uid;
            return userProfileRequest;
        }

        public override HttpRequestMessage marshalUserProfileRequest(OAuth20.UserProfileRequest _UserProfileRequest)
        {
            var RawRequestUrl = UserProfileUrl + "?" + Utils.ObjectToUrlEncodedString(_UserProfileRequest);
            return new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
        }

        /*** implementing the methods for AuthenticationConclusion ***/
        protected override Type UserProfileResponseType { get { return typeof(WBUserProfileResponse); } }
        public override GenericAuth.AuthenticationConclusion createConclusion(
            OAuth20.AuthorizationResponse authorizationResponse,
            OAuth20.UserProfileResponse userProfileResponse)
        {
            var WBUserProfileResponse = (WBUserProfileResponse)userProfileResponse;
            var conclusion = new GenericAuth.AuthenticationConclusion();
            conclusion.channel = authorizationResponse.SVX_sender;
            var UserProfile = new WBUserProfile();
            UserProfile.UserID = WBUserProfileResponse.id;
            UserProfile.Email = "";
            UserProfile.FullName = WBUserProfileResponse.name;
            conclusion.userProfile = UserProfile;
            conclusion.userProfile.Authority = "Weibo.com";
            return conclusion;
        }

        public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new Weibo_RP(
                Config.config.rpPrincipal,
                Config.config.AppRegistration.Weibo.clientID,
                Config.config.agentRootUrl + "callback/Weibo",
                Config.config.AppRegistration.Weibo.clientSecret,
                "https://api.weibo.com/oauth2/authorize",
                "https://api.weibo.com/oauth2/access_token",
                "https://api.weibo.com/2/users/show.json",
                Config.config.stateSecretKey
                );
            routeBuilder.MapRoute("login/Weibo", RP.Login_StartAsync);
            routeBuilder.MapRoute("callback/Weibo", RP.AuthorizationCodeFlow_Login_CallbackAsync);
        }
    }
    public class Weibo_IdP : OAuth20.ModelAuthorizationServer
    {

        public Weibo_IdP(SVX.Entity idpPrincipal)
            : base(idpPrincipal)
        {
            // We only support facebookPrincipal.
            Contract.Assert(idpPrincipal == facebookPrincipal);
        }

        public static SVX.Entity facebookPrincipal = SVX.Entity.Of("weibo.com");

        public override OAuth20.UserProfileResponse CreateUserProfileResponse(string userID)
        {
            return new WBUserProfileResponse
            {
                id = userID,
                //email = userID,
                name = SVX.VProgram_API.Nondet<string>()
            };
        }

        public override OAuth20.AccessTokenResponse SVX_MakeAccessTokenResponse(
            OAuth20.AccessTokenRequest req, OAuth20.AuthorizationCodeParams codeParamsHint)
        {
            req.grant_type = "authorization_code";
            return base.SVX_MakeAccessTokenResponse(req, codeParamsHint);
        }
    }
}
