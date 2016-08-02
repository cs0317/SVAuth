using Microsoft.AspNetCore.Routing;
using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using BytecodeTranslator.Diagnostics;
using Newtonsoft.Json.Linq;

namespace SVAuth.ServiceProviders.Microsoft
{
    public class MSAppRegistration
    {
        public string appId;
        public string appSecret;
    }
    public class MSAuthenticationRequest : OIDC10.AuthenticationRequest
    {
        public string response_mode;
    }
    public class MSJwtToken: OIDC10.JwtTokenBody
    {
        public string name, preferred_username;
    }
    public class MSUserProfile : GenericAuth.UserProfile
    {
        public string Email;
        public string FullName;
        public string MS_ID;
    }
    public class Microsoft_RP: OIDC10.RelyingParty
    {
        public Microsoft_RP(SVX.Principal rpPrincipal, string client_id1, string redierct_uri1, string client_secret1, string AuthorizationEndpointUrl1, string TokenEndpointUrl1)
        : base(rpPrincipal, client_id1, redierct_uri1, client_secret1, AuthorizationEndpointUrl1, TokenEndpointUrl1)
        {
            BypassCertification = true;
        }
        public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new Microsoft_RP(
                Config.config.rpPrincipal,
                Config.config.AppRegistration.Microsoft.appId,
                Config.config.agentRootUrl + "callback/Microsoft",
                Config.config.AppRegistration.Microsoft.appSecret,
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token"
                );
            routeBuilder.MapRoute("login/Microsoft", RP.Login_StartAsync);
            routeBuilder.MapRoute("callback/Microsoft", RP.AuthorizationCodeFlow_Login_CallbackAsync);
        }
        public override OAuth20.AuthorizationRequest createAuthorizationRequest(SVX.PrincipalFacet client)
        {
            MSAuthenticationRequest MSAuthenticationRequest = new MSAuthenticationRequest();
            MSAuthenticationRequest.client_id = client_id;
            MSAuthenticationRequest.response_type = "code";
            MSAuthenticationRequest.scope = "openid profile";
            MSAuthenticationRequest.redirect_uri = redirect_uri;
            MSAuthenticationRequest.response_mode = "form_post";
            return MSAuthenticationRequest;
        }
        public override string marshalAuthorizationRequest(OAuth20.AuthorizationRequest MSAuthenticationRequest)
        {
            return AuthorizationEndpointUrl + "?" + Utils.ObjectToUrlEncodedString(MSAuthenticationRequest);
        }

        /*** implementing the methods for AccessTokenRequest ***/
        public override OAuth20.AccessTokenRequest createAccessTokenRequest(OAuth20.AuthorizationResponse authorizationResponse)
        {
            OAuth20.AccessTokenRequest _AccessTokenRequest = new OAuth20.AccessTokenRequest();
            _AccessTokenRequest.grant_type = "authorization_code";
            _AccessTokenRequest.client_id = client_id;
            _AccessTokenRequest.code = authorizationResponse.code;
            _AccessTokenRequest.redirect_uri = redirect_uri;
            _AccessTokenRequest.client_secret = client_secret;
            return _AccessTokenRequest;
        }

        public override HttpRequestMessage marshalAccessTokenRequest(OAuth20.AccessTokenRequest _AccessTokenRequest)
        {
            HttpRequestMessage requestMessage = new HttpRequestMessage();
            requestMessage.Method = HttpMethod.Post;
            requestMessage.Content = Utils.ObjectToUrlEncodedContent(_AccessTokenRequest);
            requestMessage.RequestUri = new Uri(TokenEndpointUrl);
            return requestMessage;

        }

        protected override void set_parse_id_token(SVX.SVX_MSG msg, JObject id_token)
        {
            ((OIDC10.TokenResponse)msg).parsed_id_token = Utils.UnreflectObject<MSJwtToken>(id_token);
        }
        /*** implementing the methods for AuthenticationConclusion ***/
        public override GenericAuth.AuthenticationConclusion createConclusionOidc(
            OAuth20.AuthorizationResponse authorizationResponse,
            OIDC10.TokenResponse tokenResponse)
        {
            var AuthConclusion = new GenericAuth.AuthenticationConclusion();
            AuthConclusion.authenticatedClient = authorizationResponse.SVX_sender;
            var userProfile = new MSUserProfile();
            MSJwtToken jwtToken = (MSJwtToken)tokenResponse.parsed_id_token;
            userProfile.UserID = jwtToken.preferred_username;
            userProfile.Email = jwtToken.preferred_username;
            userProfile.MS_ID = jwtToken.sub;
            userProfile.FullName = jwtToken.name;
            AuthConclusion.userProfile = userProfile;
            return AuthConclusion;
        }
    }
}


