using Microsoft.AspNetCore.Routing;
using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using BytecodeTranslator.Diagnostics;
using System.IO;

namespace SVAuth.ServiceProviders.CILogon
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
        public string sub;
        public string given_name, family_name, email;
    }

    public class CILogon_RP : OAuth20.Client
    {
        public string UserProfileUrl;
        public CILogon_RP(SVX.Entity rpPrincipal,
            string client_id1 = null, string redierct_uri1 = null, string client_secret1 = null,
            string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null, string UserProfileUrl1 = null,
            string stateKey = null)
        : base(rpPrincipal, client_id1, redierct_uri1, client_secret1, AuthorizationEndpointUrl1, TokenEndpointUrl1, stateKey)
        {
            UserProfileUrl = UserProfileUrl1;
        }
        protected override Type AccessTokenResponseType { get { return typeof(AccessTokenResponse); } }
        protected override OAuth20.ModelAuthorizationServer CreateModelAuthorizationServer() =>
            new CILogon_IdP(CILogon_IdP.cilogonPrincipal);

        /*** implementing the methods for AuthorizationRequest ***/
        public override OAuth20.AuthorizationRequest createAuthorizationRequest(SVX.Channel client)
        {
            var authorizationRequest = new OAuth20.AuthorizationRequest();
            authorizationRequest.client_id = client_id;      
            authorizationRequest.response_type = "code";
            authorizationRequest.scope = "openid profile email org.cilogon.userinfo";
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
            var RawRequestUrl = UserProfileUrl + "?" + Utils.ObjectToUrlEncodedString(_UserProfileRequest);
            return new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
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
            UserProfile.UserID = UserProfileResponse.sub;
            UserProfile.Email = UserProfileResponse.email;
            UserProfile.FullName = UserProfileResponse.given_name + " " + UserProfileResponse.family_name;
            conclusion.userProfile = UserProfile;
            conclusion.userProfile.Authority = "CILogon.org";
            return conclusion;
        }

        public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new CILogon_RP(
                Config.config.rpPrincipal,
                Config.config.AppRegistration.CILogon.clientID,
                Config.config.agentRootUrl + "callback/CILogon",
                Config.config.AppRegistration.CILogon.clientSecret,
                "https://cilogon.org/authorize",
                "https://cilogon.org/oauth2/token",
                "https://cilogon.org/oauth2/userinfo",
                Config.config.stateSecretKey
                );
            routeBuilder.MapRoute("login/CILogon", RP.Login_StartAsync);
            routeBuilder.MapRoute("callback/CILogon", RP.AuthorizationCodeFlow_Login_CallbackAsync);
        }
    }
    public class CILogon_IdP : OAuth20.ModelAuthorizationServer
    {

        public CILogon_IdP(SVX.Entity idpPrincipal)
            : base(idpPrincipal)
        {
            // We only support facebookPrincipal.
            Contract.Assert(idpPrincipal == cilogonPrincipal);
        }

        public static SVX.Entity cilogonPrincipal = SVX.Entity.Of("CILogon.org");

        public override OAuth20.UserProfileResponse CreateUserProfileResponse(string userID)
        {
            return new UserProfileResponse
            {
                sub = userID,
                //email = userID,
                given_name = SVX.VProgram_API.Nondet<string>(),
                family_name = SVX.VProgram_API.Nondet<string>(),
                email = SVX.VProgram_API.Nondet<string>()
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
