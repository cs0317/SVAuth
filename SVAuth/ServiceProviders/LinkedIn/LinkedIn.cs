using Microsoft.AspNetCore.Routing;
using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using BytecodeTranslator.Diagnostics;
using System.IO;

namespace SVAuth.ServiceProviders.LinkedIn
{
    public class AppRegistration
    {
        public string clientID;
        public string clientSecret;
    }

    class DebugTokenRequest
    {
    }
    public class AccessTokenResponse : OAuth20.AccessTokenResponse
    {
        public string uid;
    }
    public class UserProfile : GenericAuth.UserProfile
    {
        public string Email;
        public string FullName;
    }
    
    public class UserProfileResponse : OAuth20.UserProfileResponse
    {
        public string id;
        public string firstName,lastName,emailAddress;
    }

    public class LinkedIn_RP : OAuth20.Client
    {
        public string UserProfileUrl;
        public LinkedIn_RP(SVX.Entity rpPrincipal,
            string client_id1 = null, string redierct_uri1 = null, string client_secret1 = null,
            string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null, string UserProfileUrl1 = null,
            string stateKey = null)
        : base(rpPrincipal, client_id1, redierct_uri1, client_secret1, AuthorizationEndpointUrl1, TokenEndpointUrl1, stateKey)
        {
            UserProfileUrl = UserProfileUrl1;
        }
        protected override Type AccessTokenResponseType { get { return typeof(AccessTokenResponse); } }
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
            authorizationRequest.scope = "r_basicprofile r_emailaddress";
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
            return new HttpRequestMessage(HttpMethod.Post, RawRequestUrl);
        }

        /*** implementing the methods for UserProfileRequest ***/
        public override OAuth20.UserProfileRequest createUserProfileRequest(OAuth20.AccessTokenResponse accessTokenResponse)
        {
            OAuth20.UserProfileRequest userProfileRequest = new OAuth20.UserProfileRequest();
            userProfileRequest.access_token = accessTokenResponse.access_token;
            return userProfileRequest;
        }

        public override HttpRequestMessage marshalUserProfileRequest(OAuth20.UserProfileRequest _UserProfileRequest)
        {
            var RawRequestUrl = UserProfileUrl + "?" + "format=json";
            var req = new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
            req.Headers.Add("Authorization", "Bearer " + _UserProfileRequest.access_token);
            return req;
        }

        /*** implementing the methods for AuthenticationConclusion ***/
        protected override Type UserProfileResponseType { get { return typeof(UserProfileResponse); } }
        public override GenericAuth.AuthenticationConclusion createConclusion(
            OAuth20.AuthorizationResponse authorizationResponse,
            OAuth20.UserProfileResponse userProfileResponse)
        {
            var UserProfileResponse = (UserProfileResponse)userProfileResponse;
            var conclusion = new GenericAuth.AuthenticationConclusion();
            conclusion.channel = authorizationResponse.SVX_sender;
            var UserProfile = new UserProfile();
            UserProfile.UserID = UserProfileResponse.id;
            UserProfile.Email = UserProfileResponse.emailAddress;
            UserProfile.FullName = UserProfileResponse.firstName + " " + UserProfileResponse.lastName;
            conclusion.userProfile = UserProfile;
            conclusion.userProfile.Authority = "LinkedIn.com";
            return conclusion;
        }

        public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new LinkedIn_RP(
                Config.config.rpPrincipal,
                Config.config.AppRegistration.LinkedIn.clientID,
                Config.config.agentRootUrl + "callback/LinkedIn",
                Config.config.AppRegistration.LinkedIn.clientSecret,
                "https://www.linkedin.com/oauth/v2/authorization",
                "https://www.linkedin.com/oauth/v2/accessToken",
                "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,email-address)",
                Config.config.stateSecretKey
                );
            routeBuilder.MapRoute("login/LinkedIn", RP.Login_StartAsync);
            routeBuilder.MapRoute("callback/LinkedIn", RP.AuthorizationCodeFlow_Login_CallbackAsync);
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
            return new UserProfileResponse
            {
                id = userID,
                //email = userID,
                firstName = SVX.VProgram_API.Nondet<string>(),
                lastName = SVX.VProgram_API.Nondet<string>(),
                emailAddress = SVX.VProgram_API.Nondet<string>()
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
