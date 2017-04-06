using Microsoft.AspNetCore.Routing;
using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using BytecodeTranslator.Diagnostics;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SVAuth.OIDC10;
using SVX;

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
    public class GGJwtToken : OIDC10.JwtTokenBody
    {
        public string name, email, email_verified;
    }
    public class GGUserProfile : GenericAuth.UserProfile
    {
        public string Email;
        public string FullName;
        public string GG_ID;
    }

    public class GoogleTokenVerifier : OIDC10.OIDCTokenVerifier
    {
        public string SignatureValidationUrl;
        public override OIDC10.JwtTokenBody UnReflectJwtTokenBody(JObject obj)
        {
            return (OIDC10.JwtTokenBody)(Utils.UnreflectObject<GGJwtToken>(obj));
        }

        protected override JwtTokenBody RawVerifyAndExtract(string secretValue)
        {
            var RawRequestUrl = SignatureValidationUrl + "?id_token=" + secretValue;
            var rawReq = new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
            var RawResponse = Utils.PerformHttpRequestAsync(rawReq).Result;
            if (RawResponse.StatusCode != System.Net.HttpStatusCode.OK)
                throw new Exception();
            JObject jObj = JObject.Parse(RawResponse.Content.ReadAsStringAsync().Result);
            return Utils.UnreflectObject<GGJwtToken>(jObj);
        }

        public GoogleTokenVerifier()
        {
            IdPPrincipal = Google_IdP.GooglePrincipal;
        }

    }

    public class MessageStructures : OIDC10.MessageStructures
    {
        internal GoogleTokenVerifier GoogleTokenVerifier = new GoogleTokenVerifier()
            { SignatureValidationUrl = "https://www.googleapis.com/oauth2/v3/tokeninfo"};
        protected override OIDC10.OIDCTokenVerifier getTokenVerifier()
        { return GoogleTokenVerifier; }
        public MessageStructures(SVX.Entity idpPrincipal) : base(idpPrincipal) { }
    }
    public class Google_RP : OIDC10.RelyingParty
    {
        public string UserProfileUrl, SignatureValidationUrl;

        public Google_RP(SVX.Entity rpPrincipal, string client_id1=null, string return_uri1 = null, string client_secret1 = null,
                         string AuthorizationEndpointUrl1 = null, string UserProfileUrl1 = null, string SignatureValidationUrl1 = null, string stateKey = null)
        : base(rpPrincipal, client_id1, return_uri1, client_secret1, AuthorizationEndpointUrl1, null, stateKey)
        {
            //BypassCertification = true;
            UserProfileUrl = UserProfileUrl1;
            SignatureValidationUrl = SignatureValidationUrl1;

        }
        public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new Google_RP(
                Config.config.rpPrincipal,
                Config.config.AppRegistration.Google.clientID,
                Config.config.agentRootUrl + "callback/Google",
                Config.config.AppRegistration.Google.clientSecret,
                "https://accounts.google.com/o/oauth2/auth",
                "https://www.googleapis.com/oauth2/v2/userinfo",
                "https://www.googleapis.com/oauth2/v3/tokeninfo",
                Config.config.stateSecretKey);
            routeBuilder.MapRoute("login/Google", RP.Login_StartAsync);
            routeBuilder.MapRoute("callback/Google", RP.ImplicitFlow_Login_CallbackAsync);
        }

        protected override ModelOIDCAuthenticationServer CreateModelOIDCAuthenticationServer()
        {
            return new Google_IdP(Google_IdP.GooglePrincipal);
        }

        public override OIDC10.MessageStructures GetMessageStructures()
        {
            return new MessageStructures(Google_IdP.GooglePrincipal);
        }
        public override OAuth20.AuthorizationRequest createAuthorizationRequest(SVX.Channel client)
        {
            GGAuthenticationRequest GGAuthenticationRequest = new GGAuthenticationRequest();
            GGAuthenticationRequest.client_id = client_id;
            GGAuthenticationRequest.response_type = "id_token token";
            GGAuthenticationRequest.scope = "openid email profile";
            GGAuthenticationRequest.redirect_uri = redirect_uri;
            GGAuthenticationRequest.response_mode = "form_post";
            var stateParams = new OAuth20.StateParams
            {
                client = client,
                idpPrincipal = idpParticipantId.principal
            };
            GGAuthenticationRequest.state = stateGenerator.Generate(stateParams, SVX_Principal);
            HashAlgorithm hashAlgo = SHA1.Create();
            GGAuthenticationRequest.nonce = BitConverter.ToString(hashAlgo.ComputeHash(System.Text.Encoding.UTF8.GetBytes(client.id)));
            return GGAuthenticationRequest;
        }
        public override string marshalAuthorizationRequest(OAuth20.AuthorizationRequest MSAuthenticationRequest)
        {
            return AuthorizationEndpointUrl + "?" + Utils.ObjectToUrlEncodedString(MSAuthenticationRequest);
        }
        protected string getFullName(string access_token)
        {
            var RawRequestUrl = UserProfileUrl + "?access_token=" + access_token;
            var rawReq = new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
            var RawResponse = Utils.PerformHttpRequestAsync(rawReq).Result;
            return (string)(JObject.Parse(RawResponse.Content.ReadAsStringAsync().Result)["name"]);
        }
        /*** implementing the methods for AuthenticationConclusion ***/
        public override GenericAuth.AuthenticationConclusion createConclusionOidcImplicit(
            OIDC10.AuthenticationResponse_with_id_token authenticationResponse)
        {
            var AuthConclusion = new GenericAuth.AuthenticationConclusion();
            AuthConclusion.channel = authenticationResponse.SVX_sender;
            OIDC10.JwtTokenBody jwtTokenBody = authenticationResponse.id_token.theParams;
            if (jwtTokenBody.aud != this.client_id)
                throw new Exception("client_id in the jwtToken is not of this relying party.");
            var userProfile = new GGUserProfile();
            userProfile.UserID = ((GGJwtToken)jwtTokenBody).sub;
            userProfile.Email = ((GGJwtToken)jwtTokenBody).email;
            userProfile.GG_ID = ((GGJwtToken)jwtTokenBody).sub;
            userProfile.FullName = getFullName(authenticationResponse.access_token);

            //checking CSRF_state
            var stateParams = new OAuth20.StateParams
            {
                client = authenticationResponse.SVX_sender,
                idpPrincipal = idpParticipantId.principal
            };
            stateGenerator.Verify(stateParams, authenticationResponse.state);

            AuthConclusion.userProfile = userProfile;
            AuthConclusion.userProfile.Authority = "Google.com";
            return AuthConclusion;
        }
    }

    public class Google_IdP : ModelOIDCAuthenticationServer
    {
        public static Entity GooglePrincipal = SVX.Entity.Of("accounts.google.com");
        public Google_IdP(Entity idpPrincipal) : base(idpPrincipal)
        {
        }

        protected override OIDC10.MessageStructures getMessageStrctures()
        {
            return new MessageStructures(SVX_Principal);
        }

        protected override OIDCTokenVerifier getTokenGenerator()
        {
            return new GoogleTokenVerifier();
        }
    }
}


