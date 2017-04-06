using Microsoft.AspNetCore.Routing;
using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using BytecodeTranslator.Diagnostics;
using System.IO;

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
    public class FBUserProfile : GenericAuth.UserProfile
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
        public Facebook_RP(SVX.Entity rpPrincipal,
            string client_id1 = null, string redierct_uri1 = null, string client_secret1 = null,
            string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null, string UserProfileUrl1 = null,
            string stateKey = null)
        : base(rpPrincipal, client_id1, redierct_uri1, client_secret1, AuthorizationEndpointUrl1, TokenEndpointUrl1, stateKey)
        {
            UserProfileUrl = UserProfileUrl1;
        }

        protected override OAuth20.ModelAuthorizationServer CreateModelAuthorizationServer() =>
            new Facebook_IdP(Facebook_IdP.facebookPrincipal);

        // Very little of this is Facebook-specific.  Consider moving it to
        // OAuth20.  (Exception: it's unclear if the user profile request is an
        // OAuth20 concept at all, so maybe the entirety of that should move to
        // Facebook with only a hook remaining in OAuth20.)

        /*** implementing the methods for AuthorizationRequest ***/
        public override OAuth20.AuthorizationRequest createAuthorizationRequest(SVX.Channel client)
        {
            var authorizationRequest = new FBAuthorizationRequest();
            authorizationRequest.client_id = client_id;      
            authorizationRequest.response_type = "code";
            authorizationRequest.scope = "user_about_me email";
            authorizationRequest.redirect_uri = redirect_uri;
            authorizationRequest.type = "web_server";
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
            return AuthorizationEndpointUrl + "?" + Utils.ObjectToUrlEncodedString(authorizationRequest);
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
            //Facebook's access token request doesn't need "grant_type=authorization_code". 
            //See https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow
            _AccessTokenRequest.client_id = client_id;
            _AccessTokenRequest.code = authorizationResponse.code;
            _AccessTokenRequest.redirect_uri = redirect_uri;
            _AccessTokenRequest.client_secret = client_secret;
            return _AccessTokenRequest;
        }

        public override HttpRequestMessage marshalAccessTokenRequest(OAuth20.AccessTokenRequest accessTokenRequest)
        {
            var RawRequestUrl = TokenEndpointUrl + "?" + Utils.ObjectToUrlEncodedString(accessTokenRequest);
            return new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
        }

        /*** implementing the methods for UserProfileRequest ***/
        public override OAuth20.UserProfileRequest createUserProfileRequest(OAuth20.AccessTokenResponse accessTokenResponse)
        {
            OAuth20.UserProfileRequest userProfileRequest = new OAuth20.UserProfileRequest();
            userProfileRequest.access_token = accessTokenResponse.access_token;
            userProfileRequest.fields = "name,email";
            return userProfileRequest;
        }

        public override HttpRequestMessage marshalUserProfileRequest(OAuth20.UserProfileRequest _UserProfileRequest)
        {
            var RawRequestUrl = UserProfileUrl + "?" + Utils.ObjectToUrlEncodedString(_UserProfileRequest);
            return new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
        }

        /*** implementing the methods for AuthenticationConclusion ***/
        protected override Type UserProfileResponseType { get { return typeof(FBUserProfileResponse); } }
        public override GenericAuth.AuthenticationConclusion createConclusion(
            OAuth20.AuthorizationResponse authorizationResponse,
            OAuth20.UserProfileResponse userProfileResponse)
        {
            var fbUserProfileResponse = (FBUserProfileResponse)userProfileResponse;
            var conclusion = new GenericAuth.AuthenticationConclusion();
            conclusion.channel = authorizationResponse.SVX_sender;
            var fbUserProfile = new FBUserProfile();
            fbUserProfile.UserID = fbUserProfileResponse.id;
            fbUserProfile.Email = fbUserProfileResponse.email;
            fbUserProfile.FB_ID = fbUserProfileResponse.id;
            fbUserProfile.FullName = fbUserProfileResponse.name;
            conclusion.userProfile = fbUserProfile;
            conclusion.userProfile.Authority = "Facebook.com";
            return conclusion;
        }

        public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new Facebook_RP(
                Config.config.rpPrincipal,
                Config.config.AppRegistration.Facebook.appId,
                Config.config.agentRootUrl + "callback/Facebook",
                Config.config.AppRegistration.Facebook.appSecret,
                "https://www.facebook.com/v2.0/dialog/oauth",
                "https://graph.facebook.com/v2.3/oauth/access_token",
                "https://graph.facebook.com/v2.5/me",
                Config.config.stateSecretKey
                );
            routeBuilder.MapRoute("login/Facebook", RP.Login_StartAsync);
            routeBuilder.MapRoute("callback/Facebook", RP.AuthorizationCodeFlow_Login_CallbackAsync);
        }
    }
    public class Facebook_IdP : OAuth20.ModelAuthorizationServer
    {

        public Facebook_IdP(SVX.Entity idpPrincipal)
            : base(idpPrincipal)
        {
            // We only support facebookPrincipal.
            Contract.Assert(idpPrincipal == facebookPrincipal);
        }

        public static SVX.Entity facebookPrincipal = SVX.Entity.Of("facebook.com");

        public override OAuth20.UserProfileResponse CreateUserProfileResponse(string userID)
        {
            return new FBUserProfileResponse
            {
                id = userID,
                email = SVX.VProgram_API.Nondet<string>(),
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
