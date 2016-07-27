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

#if false
    public class ID_Claim : OAuth20.ID_Claim
    {
       public string email, FB_ID, FullName;
       public override string  GetUserID(string UserID_Field_Name)
        {
            switch (UserID_Field_Name)
            {
                case "email":
                    return email;
                case "FB_ID":
                    return FB_ID;
                default: return "blah-blah-blah";
            }
        }
    }
#endif
    public class Facebook_RP : OAuth20.Client
    {
        public string UserProfileUrl;
        public Facebook_RP(SVX.Principal rpPrincipal,
            string client_id1 = null, string redierct_uri1 = null, string client_secret1 = null,
            string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null, string UserProfileUrl1 = null,
            string stateKey = null)
        : base(rpPrincipal, client_id1, redierct_uri1, client_secret1, AuthorizationEndpointUrl1, TokenEndpointUrl1, stateKey)
        {
            UserProfileUrl = UserProfileUrl1;
        }

        protected override OAuth20.ModelAuthorizationServer CreateModelAuthorizationServer() =>
            new Facebook_IdP_Default(Facebook_IdP_Default.facebookPrincipal);

        // Very little of this is Facebook-specific.  Consider moving it to
        // OAuth20.  (Exception: it's unclear if "user profile" is an OAuth20
        // concept at all, so maybe the entirety of that should move to Facebook
        // with only a hook remaining in OAuth20.)

        /*** implementing the methods for AuthorizationRequest ***/
        public override OAuth20.AuthorizationRequest createAuthorizationRequest(SVX.PrincipalFacet client)
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
            conclusion.authenticatedClient = authorizationResponse.SVX_sender;
            var fbUserProfile = new FBUserProfile();
            fbUserProfile.UserID = fbUserProfileResponse.email;
            fbUserProfile.Email = fbUserProfileResponse.email;
            fbUserProfile.FB_ID = fbUserProfileResponse.id;
            fbUserProfile.FullName = fbUserProfileResponse.name;
            conclusion.userProfile = fbUserProfile;
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
    public class Facebook_IdP_Default : OAuth20.ModelAuthorizationServer
    {
#if false
        static OAuth20.NondetOAuth20 Nondet;
        //string UserID_Field_Name = "FB_ID";

        public interface NondetFB
        { Dictionary<string, Dictionary<string, ID_Claim>> StringStringIDClaim();
            ID_Claim ID_Claim();
        }
        static NondetFB Nondet_FB;
        class ID_Claims: GenericAuth.IdPAuthRecords_Base
        {
            Dictionary<string, Dictionary<string, ID_Claim>> ID_Claims_Dictionary ;
            public GenericAuth.ID_Claim getEntry(string IdPSessionSecret, string client_id)
            {
                Dictionary<string, Dictionary<string, ID_Claim>> ID_Claims_Dictionary2 = ID_Claims_Dictionary;

                BCTDiagnostics.Record("ID_Claims", ID_Claims_Dictionary2);
                BCTDiagnostics.Record("IdPSessionSecret", IdPSessionSecret);
                BCTDiagnostics.Record("client_id", client_id);
                BCTDiagnostics.Record("ID_Claims_Dictionary[IdPSessionSecret][client_id]", ID_Claims_Dictionary[IdPSessionSecret][client_id]);
                BCTDiagnostics.Record("ID_Claims_Dictionary[IdPSessionSecret]", ID_Claims_Dictionary[IdPSessionSecret]);
                ID_Claim ID_Claim = ID_Claims_Dictionary[IdPSessionSecret][client_id];
                Contract.Assume(ID_Claim.GetType() == typeof(ID_Claim));  //This "Assume" is needed because we cannot "new OAuth20.ID_Claim" here.
                return ID_Claim;
            }
            public bool setEntry(string IdPSessionSecret, string client_id, GenericAuth.ID_Claim ID_Claim1)
            {
                ID_Claim ID_Claim = (ID_Claim)ID_Claim1;
                if (ID_Claim == null)
                    return false;
                ID_Claims_Dictionary[IdPSessionSecret] = new Dictionary<string, ID_Claim>();
                ID_Claims_Dictionary[IdPSessionSecret][client_id] = ID_Claim;
                return true;
            }

            public ID_Claims()
            {
                ID_Claims_Dictionary = new Dictionary<string, Dictionary<string, ID_Claim>>();
                setEntry("randomIdPSessID", "randomClientID", Nondet_FB.ID_Claim());
            }
        }
#endif

        public Facebook_IdP_Default(SVX.Principal idpPrincipal)
            : base(idpPrincipal)
        {
#if false
            IdentityRecords = new ID_Claims();
#endif
            // We only support facebookPrincipal.
            Contract.Assert(idpPrincipal == facebookPrincipal);
        }

        public static SVX.Principal facebookPrincipal = SVX.Principal.Of("facebook.com");

#if false
        public override string createAccessToken(OAuth20.AuthorizationCodeEntry AuthorizationCodeEntry)
        {
            string AccessToken = Nondet.String();
            OAuth20.AccessTokenEntry AccessTokenEntry = new OAuth20.AccessTokenEntry();
            AccessTokenEntry.IdPSessionSecret = AuthorizationCodeEntry.IdPSessionSecret;
            AccessTokenEntry.client_id = AuthorizationCodeEntry.client_id;
            AccessTokenEntry.scope = AuthorizationCodeEntry.scope;

            /*    string left, right;
                  left = IdentityRecords.getEntry(AuthorizationCodeEntry.IdPSessionSecret, AuthorizationCodeEntry.client_id).Redir_dest;
                  right = GenericAuth.GlobalObjects_base.RP.Domain;
                  BCTDiagnostics.Record("left side", left);
                  BCTDiagnostics.Record("right side", right);
                  Dictionary<string, OAuth20.AccessTokenEntry> AccessTokens2 = AccessTokens;
                  BCTDiagnostics.Record("AccessTokens", AccessTokens2); 
                  System.Diagnostics.Contracts.Contract.Assert(IdentityRecords.getEntry(AuthorizationCodeEntry.IdPSessionSecret, AuthorizationCodeEntry.client_id).Redir_dest == GenericAuth.GlobalObjects_base.RP.Domain);
             */
            AccessTokens[AccessToken] = AccessTokenEntry;
            /*     left = IdentityRecords.getEntry(AuthorizationCodeEntry.IdPSessionSecret, AuthorizationCodeEntry.client_id).Redir_dest;
                 right = GenericAuth.GlobalObjects_base.RP.Domain;
                 BCTDiagnostics.Record("left side", left);
                 BCTDiagnostics.Record("right side", right);

                 System.Diagnostics.Contracts.Contract.Assert(IdentityRecords.getEntry(AuthorizationCodeEntry.IdPSessionSecret, AuthorizationCodeEntry.client_id).Redir_dest == GenericAuth.GlobalObjects_base.RP.Domain);

                 System.Diagnostics.Contracts.Contract.Assert(IdentityRecords.getEntry(AccessTokenEntry.IdPSessionSecret, AccessTokenEntry.client_id).Redir_dest == GenericAuth.GlobalObjects_base.RP.Domain);
             */
            return AccessToken;
        }
        public override OAuth20.UserProfileResponse createUserProfileResponse(OAuth20.ID_Claim ID_Claim1)
        {
            ID_Claim ID_Claim = (ID_Claim)ID_Claim1;
            if (ID_Claim == null)
                return null;
            FBUserProfileResponse UserProfileResponse = new FBUserProfileResponse();
            UserProfileResponse.id = ID_Claim.FB_ID;
            UserProfileResponse.email = ID_Claim.email;
            UserProfileResponse.name = ID_Claim.FullName;
            return UserProfileResponse;
        }
#endif
        public override OAuth20.UserProfileResponse CreateUserProfileResponse(string userID)
        {
            return new FBUserProfileResponse
            {
                id = SVX.VProgram_API.Nondet<string>(),
                email = userID,
                name = SVX.VProgram_API.Nondet<string>()
            };
        }

        public override OAuth20.AccessTokenResponse SVX_MakeAccessTokenResponse(
            OAuth20.AccessTokenRequest req, OAuth20.AuthorizationCodeParams codeParamsHint)
        {
#if false
            //Assumptions
            OAuth20.AuthorizationCodeEntry entry = AuthorizationCodes[req.code];
            //Assumption1: when facebook.com use the code to retrieve the client_id and the IdPSessionSecret, they are the ones for the SignInIdP
            System.Diagnostics.Contracts.Contract.Assume(entry.client_id == GenericAuth.GlobalObjects_base.SignInIdP_Req.Realm);
            System.Diagnostics.Contracts.Contract.Assume(entry.IdPSessionSecret == GenericAuth.GlobalObjects_base.SignInIdP_Req.IdPSessionSecret);
#endif
            req.grant_type = "authorization_code";
            return base.SVX_MakeAccessTokenResponse(req, codeParamsHint);
        }

#if false
        //Currently, the following two methods are essentially "unimplemented", because the SignInIdP call will be tossed away from the onion anyways. 
        //Perhaps there are some future scenarios in which these two methods need to be implemented. 
        public override GenericAuth.SignInIdP_Resp_SignInRP_Req Redir(string dest, GenericAuth.ID_Claim _ID_Claim)
        {
            return null;
        }
        public override OAuth20.ID_Claim get_ID_Claim_From_Authorization_Request(OAuth20.AuthorizationRequest req)
        {
            return null;
        }
#endif
    }
    /*
    public class Facebook_IdP_Email_As_UserID : Facebook_IdP_Default
    {
        string UserID_Field_Name = "email";
    }*/
}
