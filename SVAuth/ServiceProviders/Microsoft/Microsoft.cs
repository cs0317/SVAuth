using Microsoft.AspNetCore.Routing;
using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using BytecodeTranslator.Diagnostics;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using SVAuth.OIDC10;
using SVX;

namespace SVAuth.ServiceProviders.Microsoft
{
    public class MSAppRegistration
    {
        public string appId;
        public string appSecret;
    }
    public class MSJwtToken : OIDC10.JwtTokenBody
    {
        public string name, preferred_username, unique_name, upn;
    }

    public class MSAuthenticationRequest: OIDC10.AuthenticationRequest
    {
        public string tParam = "eyJpZF90b2tlbl9pbnZhbGlkX2NfaGFzaCI6IHRydWV9";
        // "e2lkX3Rva2VuX2ludmFsaWRfbm9uY2UgOiB0cnVlfQ";    //used by the Azure testing IdP only
    }
    public class MSUserProfile : GenericAuth.UserProfile
    {
        public string Email;
        public string FullName;
        public string MS_ID;
    }

    [BCTOmit]
    public class MessageStructures : OIDC10.MessageStructures
    {
        internal MicrosoftJwTTokenGenerator MicrosoftJwTTokenGenerator = new MicrosoftJwTTokenGenerator();
        protected override OIDC10.OIDCTokenVerifier getTokenVerifier()
        { return MicrosoftJwTTokenGenerator; }
        public MessageStructures(SVX.Entity idpPrincipal) : base(idpPrincipal) { }
    }

    public class MicrosoftJwTTokenGenerator : OIDC10.OIDCTokenVerifier
    {
        public string SignatureValidationUrl;
        public override OIDC10.JwtTokenBody UnReflectJwtTokenBody(JObject obj)
        {
            return (OIDC10.JwtTokenBody)(Utils.UnreflectObject<MSJwtToken>(obj));
        }

        protected override JwtTokenBody RawVerifyAndExtract(string secretValue)
        {
            throw new NotImplementedException();
        }

        public MicrosoftJwTTokenGenerator()
        {
            IdPPrincipal = Microsoft_IdP.MicrosoftPrincipal;
        }

    }

    public class Microsoft_RP: OIDC10.RelyingParty
    {
        public Microsoft_RP(SVX.Entity rpPrincipal, string client_id1 = null, string redierct_uri1 = null, string client_secret1 = null, string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null, string stateKey = null)
        : base(rpPrincipal, client_id1, redierct_uri1, client_secret1, AuthorizationEndpointUrl1, TokenEndpointUrl1,stateKey)
        {
        }

        public override OIDC10.MessageStructures GetMessageStructures()
        {
            return new MessageStructures(Microsoft_IdP.MicrosoftPrincipal);
        }
        protected override ModelOIDCAuthenticationServer CreateModelOIDCAuthenticationServer()
        {
            return new Microsoft_IdP(Microsoft_IdP.MicrosoftPrincipal);
        }
        public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new Microsoft_RP(
                Config.config.rpPrincipal,
                Config.config.AppRegistration.Microsoft.appId,
                Config.config.agentRootUrl + "callback/Microsoft",
                Config.config.AppRegistration.Microsoft.appSecret,
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                Config.config.stateSecretKey);
            routeBuilder.MapRoute("login/Microsoft", RP.Login_StartAsync);
            routeBuilder.MapRoute("callback/Microsoft", RP.AuthorizationCodeFlow_Login_CallbackAsync);
        }
        public override OAuth20.AuthorizationRequest createAuthorizationRequest(SVX.Channel client)
        {
            MSAuthenticationRequest AuthenticationRequest = new MSAuthenticationRequest();
            AuthenticationRequest.client_id = client_id;
            AuthenticationRequest.response_type = "code";
            AuthenticationRequest.scope = "openid profile";
            AuthenticationRequest.redirect_uri = redirect_uri;
            AuthenticationRequest.response_mode = "form_post";

            var stateParams = new OAuth20.StateParams
            {
                client = client,
                idpPrincipal = idpParticipantId.principal
            };
            AuthenticationRequest.state = stateGenerator.Generate(stateParams, SVX_Principal);

            HashAlgorithm  hashAlgo = SHA1.Create();
            AuthenticationRequest.nonce= BitConverter.ToString (hashAlgo.ComputeHash(System.Text.Encoding.UTF8.GetBytes(client.id)));

            return AuthenticationRequest;
        }
        public override string marshalAuthorizationRequest(OAuth20.AuthorizationRequest AuthenticationRequest)
        {
            return AuthorizationEndpointUrl + "?" + Utils.ObjectToUrlEncodedString((MSAuthenticationRequest)AuthenticationRequest);
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

            var stateParams = new OAuth20.StateParams
            {
                client = authorizationResponse.SVX_sender,
                idpPrincipal = idpParticipantId.principal
            };
            stateGenerator.Verify(stateParams, authorizationResponse.state);

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

        /*** implementing the methods for AuthenticationConclusion ***/
        public override GenericAuth.AuthenticationConclusion createConclusionOidc(
            OAuth20.AuthorizationResponse authorizationResponse,
            OIDC10.TokenResponse tokenResponse)
        {
            var AuthConclusion = new GenericAuth.AuthenticationConclusion();
            AuthConclusion.channel = authorizationResponse.SVX_sender;
            var userProfile = new MSUserProfile();
            MSJwtToken jwtToken = (MSJwtToken)tokenResponse.id_token.theParams;
            
            userProfile.Email = jwtToken.preferred_username;
            if (userProfile.Email == null)
                userProfile.Email = jwtToken.unique_name;
            if (userProfile.Email == null)
                userProfile.Email = jwtToken.upn;
            userProfile.MS_ID = jwtToken.sub;
            userProfile.FullName = jwtToken.name;

            userProfile.UserID = userProfile.Email;

            AuthConclusion.userProfile = userProfile;
            AuthConclusion.userProfile.Authority = "Microsoft.com";
            return AuthConclusion;
        }
    }
    public class Microsoft_IdP : ModelOIDCAuthenticationServer
    {
        public static Entity MicrosoftPrincipal = SVX.Entity.Of("login.microsoftonline.com");
        public Microsoft_IdP(Entity idpPrincipal) : base(idpPrincipal)
        {
        }

        protected override OIDC10.MessageStructures getMessageStrctures()
        {
            return new MessageStructures(SVX_Principal);
        }

        protected override OIDCTokenVerifier getTokenGenerator()
        {
            throw new NotImplementedException();
        }
    }
}


