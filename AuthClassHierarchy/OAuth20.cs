using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Diagnostics;

namespace SVAuth.OAuth20
{

    /***********************************************************/
    /*               Messages between parties                  */
    /***********************************************************/

    public class AuthorizationRequest : GenericAuth.SignInIdP_Req
    {
        public string response_type;
        public string client_id;
        public override string Realm
        {
            get { return client_id; }
            set { client_id = value; }
        }
        public string redirect_uri = null;
        public string scope;
        // Nothing references this.  Just remove it rather than exclude it from
        // serialization? ~ Matt 2016-06-01
        //public string state = null;
    }

    public class AuthorizationResponse : GenericAuth.SignInIdP_Resp_SignInRP_Req
    {
        public string code;
        public string state = null;

        public AuthorizationResponse(AuthorizationResponse srcObj = null)
        {
            if (srcObj != null)
            {
                code = srcObj.code;
                state = srcObj.state;
                SymT = srcObj.SymT;
                SignedBy = srcObj.SignedBy;
            }
        }
    }

    public class AuthorizationErrorResponse : GenericAuth.SignInIdP_Resp_SignInRP_Req
    {
        protected string error;
        protected string error_description = null;
        protected string error_uri = null;
        protected string state = null;
    }

    public class AccessTokenRequest : SVX.SVX_MSG
    {
        public string grant_type;
        public string code;
        public string redirect_uri;
        public string client_id;
        public string client_secret;
        public string refresh_token = null;
    }

    public class AccessTokenResponse : SVX.SVX_MSG
    {
        public string access_token;
        public string token_type;
        public string expires_in;
        public string refresh_token = null;
        public AccessTokenResponse(AccessTokenResponse srcObj = null)
        {
            if (srcObj != null)
            {
                access_token = srcObj.access_token;
                token_type = srcObj.token_type;
                expires_in = srcObj.expires_in;
                refresh_token = srcObj.refresh_token;
                SymT = srcObj.SymT;
                SignedBy = srcObj.SignedBy;
            }
        }
    }

    public class UserProfileRequest : SVX.SVX_MSG
    {
        public string fields;
        public string access_token;
    }
    public class UserProfileResponse : SVX.SVX_MSG
    {
    }
    public class LoginResponse : GenericAuth.SignInRP_Resp
    {
        public string status;
    }

    /***********************************************************/
    /*               Data structures on parties                */
    /***********************************************************/

    // Change to abstract because UserID is not yet defined. ~ Matt 2016-05-31
    public abstract class AuthorizationCodeEntry : GenericAuth.ID_Claim
    {
        //Note: property UserID is not defined in OAuth. It is supposed to be defined at a more concrete level.
        public string code;
        public string primaryUID;
        public string redirect_uri;
        public override string Redir_dest
        {
            get { return redirect_uri; }
        }
        public string scope;
        public string state;
    }

    public abstract class AccessTokenEntry : GenericAuth.ID_Claim
    {
        //Note: property UserID is not defined in OAuth. It is supposed to be defined at a more concrete level.
        public string access_token;
        public string primaryUID;
        public string redirect_uri;
        public override string Redir_dest
        {
            get { return redirect_uri; }
        }
        public string scope;
        public string refresh_token = null;
        public string state;
        /* string client_id;
         get Realm(): string { return this.client_id; };
         set Realm(string value) { this.client_id = value; };
         */
    }

    public interface AuthorizationCodeRecs : GenericAuth.IdPAuthRecords_Base
    {
        string findISSByClientIDAndCode(string client_id, string authorization_code);
    }

    public interface AccessTokenRecs : GenericAuth.IdPAuthRecords_Base
    {
        string findISSByClientIDAndAccessToken(string client_id, string access_token);
        string findISSByClientIDAndRefreshToken(string client_id, string refresh_token);
    }

    /***********************************************************/
    /*                          Parties                        */
    /***********************************************************/
    public abstract class Client : GenericAuth.RP
    {
        public string client_id;
        public override string Realm
        {
            get { return client_id; }
            set { client_id = value; }
        }
        public string client_secret;
        public string TokenEndpointUrl;
        public string AuthorizationEndpointUrl;
        public string return_uri;
        public override string Domain
        {
            get { return return_uri; }
            set { return_uri = value; }
        }
        // Why are the parameters optional?  I don't see how this class can work without them. ~ Matt 2016-05-31
        public Client(string client_id1 = null, string return_uri1 = null, string client_secret1 = null, string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null)
        {
            client_id = client_id1;
            return_uri = return_uri1;
            client_secret = client_secret1;
            AuthorizationEndpointUrl = AuthorizationEndpointUrl1;
            TokenEndpointUrl = TokenEndpointUrl1;
        }

        /*** Methods about AuthorizationRequest ***/
        public abstract AuthorizationRequest createAuthorizationRequest(SVX.SVX_MSG inputMSG);
        public AuthorizationRequest _createAuthorizationRequest(SVX.SVX_MSG inputMSG)
        {
            var outputMSG = createAuthorizationRequest(inputMSG);
            //SVX_Ops.recordme();
            return outputMSG;
        }
        public abstract string /*Uri*/ marshalCreateAuthorizationRequest(AuthorizationRequest _AuthorizationRequest);

        /*** Methods about AccessTokenRequest ***/
        protected virtual Type LoginCallbackRequestType { get { return typeof(AuthorizationResponse); } }
        public abstract AccessTokenRequest createAccessTokenRequest(SVX.SVX_MSG inputMSG);
        public AccessTokenRequest _createAccessTokenRequest(SVX.SVX_MSG inputMSG)
        {
            var outputMSG = this.createAccessTokenRequest(inputMSG);
            //SVX_Ops.recordme();
            return outputMSG;
        }
        public abstract HttpRequestMessage marshalCreateAccessTokenRequest(AccessTokenRequest _AccessTokenRequest);

        /*** Methods about UserProfileRequest ***/
        protected virtual Type AccessTokenResponseType { get { return typeof(AccessTokenResponse); } }
        public abstract UserProfileRequest createUserProfileRequest(SVX.SVX_MSG inputMSG);
        public UserProfileRequest _createUserProfileRequest(SVX.SVX_MSG inputMSG)
        {
            var outputMSG = this.createUserProfileRequest(inputMSG);
            //SVX_Ops.recordme();
            return outputMSG;
        }
        public abstract HttpRequestMessage marshalCreateUserProfileRequest(UserProfileRequest _UserProfileRequest);

        /*** Methods about Conclusion ***/
        protected virtual Type UserProfileResponseType { get { return typeof(UserProfileResponse); } }
        public abstract GenericAuth.AuthenticationConclusion createConclusion(SVX.SVX_MSG inputMSG);
        GenericAuth.AuthenticationConclusion _createConclusion(SVX.SVX_MSG inputMSG)
        {
            var outputMSG = this.createConclusion(inputMSG);
            //SVX_Ops.recordme();
            return outputMSG;
        }

        /*************** Start defining OAuth flows ************************/
        public Task AuthorizationCodeFlow_Login_StartAsync(HttpContext context)
        {
            SVX.SVX_MSG inputMSG = new SVX.SVX_MSG();
            // This message should never contain meaningful data.
            //JsonConvert.DeserializeObject<SVX.SVX_MSG>(Utils.ReadStream(context.Request.Body));
            var _AuthorizationRequest = _createAuthorizationRequest(inputMSG);
            var rawReq = marshalCreateAuthorizationRequest(_AuthorizationRequest);
            context.Response.Redirect(rawReq);

            return Task.CompletedTask;
        }
        public async Task AuthorizationCodeFlow_Login_CallbackAsync(HttpContext context)
        {
            Trace.Write("AuthorizationCodeFlow_Login_CallbackAsync");

            // This design is following the original Auth.JS as closely as
            // possible.  Arguably, we should give concrete subclasses full
            // control of unmarshalling, just like marshalling.  The original
            // parseHttpMessage supports both requests (query) and responses,
            // but here we know which is which.
            // ~ Matt 2016-06-01
            SVX.SVX_MSG inputMSG = (SVX.SVX_MSG)Utils.UnreflectObject(
                new JObject(context.Request.Query.Select((q) => new JProperty(q.Key, q.Value.Single()))),
                LoginCallbackRequestType);
            var _AccessTokenRequest = _createAccessTokenRequest(inputMSG);
            var rawReq = marshalCreateAccessTokenRequest(_AccessTokenRequest);
            var RawAccessTokenResponse = await Utils.PerformHttpRequestAsync(rawReq);
            Trace.Write("Got AccessTokenResponse");

            SVX.SVX_MSG inputMSG2 = (SVX.SVX_MSG)JsonConvert.DeserializeObject(
                Utils.ReadContent(RawAccessTokenResponse.Content), AccessTokenResponseType);
            var _UserProfileRequest = _createUserProfileRequest(inputMSG2);
            var rawReq2 = marshalCreateUserProfileRequest(_UserProfileRequest);
            var RawUserProfileResponse = await Utils.PerformHttpRequestAsync(rawReq2);
            Trace.Write("Got UserProfileResponse");

            SVX.SVX_MSG inputMSG3 = (SVX.SVX_MSG)JsonConvert.DeserializeObject(
                Utils.ReadContent(RawUserProfileResponse.Content), UserProfileResponseType);
            var conclusion = createConclusion(inputMSG3);
            await Utils.AbandonAndCreateSessionAsync(conclusion, context);
        }
    }

    public abstract class AuthorizationServer : GenericAuth.AS
    {
        public AuthorizationCodeRecs AuthorizationCodeRecs
        {
            get { return (AuthorizationCodeRecs)IdentityRecords; }
            set { IdentityRecords = value; }
        }

        public AccessTokenRecs AccessTokenRecs;

        public void init(AuthorizationCodeRecs AuthorizationCodeRecs1 = null, AccessTokenRecs AccessTokenRecs1 = null)
        {
            AuthorizationCodeRecs = AuthorizationCodeRecs1;
            AccessTokenRecs = AccessTokenRecs1;
        }

        /*
        //This method seems useless. Perhaps Daniel didn't understand that SignInIdP is implemnted in the base class.
        //It is supposed to be a concrete method, not to be overridden.
        SignInIdP(req: GenericAuth.SignInIdP_Req ): GenericAuth.SignInIdP_Resp_SignInRP_Req{
            GenericAuth.GlobalObjects_base.SignInIdP_Req = req;

            if (req == null) return null;
            let req1: AuthorizationRequest = <AuthorizationRequest>req;
            var _ID_Claim: GenericAuth.ID_Claim ;

            switch (req1.response_type) {
                case "code":
                    _ID_Claim = createAuthorizationCodeEntry(req1);
                    if (this.IdentityRecords.setEntry(req1.IdPSessionSecret, req1.Realm, _ID_Claim) == false)
                        return null;
                    break;
                case "token":

                    break;
                default:
                    return null;
            }

            return this.Redir(_ID_Claim.Redir_dest, _ID_Claim);
        }
        */
        public override GenericAuth.ID_Claim Process_SignInIdP_req(GenericAuth.SignInIdP_Req req1)
        {
            AuthorizationRequest req = (AuthorizationRequest)req1;
            switch (req.response_type)
            {
                case "code":
                    return createAuthorizationCodeEntry(req);
                default:
                    return null;
            }
        }

        protected AccessTokenResponse TokenEndpoint(AccessTokenRequest req)
        {
            AccessTokenEntry AccessTokenEntry;
            string IdPSessionSecret;
            if (req == null) return null;
            AccessTokenResponse resp = new AccessTokenResponse();
            //SVX_Ops.recordme(this, req, resp);
            switch (req.grant_type)
            {
                case "authorization_code":
                    IdPSessionSecret = AuthorizationCodeRecs.findISSByClientIDAndCode(req.client_id, req.code);
                    if (IdPSessionSecret == null)
                        return null;
                    AuthorizationCodeEntry AuthCodeEntry = (AuthorizationCodeEntry)AuthorizationCodeRecs.getEntry(IdPSessionSecret, req.client_id);
                    if (AuthCodeEntry.redirect_uri != req.redirect_uri)
                        return null;
                    AccessTokenEntry = createAccessTokenEntry(AuthCodeEntry.redirect_uri, AuthCodeEntry.scope, AuthCodeEntry.state);
                    if (AccessTokenRecs.setEntry(AccessTokenEntry.access_token, req.client_id, AccessTokenEntry) == false)
                        return null;

                    resp.access_token = AccessTokenEntry.access_token;
                    resp.refresh_token = AccessTokenEntry.refresh_token;
                    return resp;
                case "refresh_token":
                    IdPSessionSecret = AccessTokenRecs.findISSByClientIDAndRefreshToken(req.client_id, req.refresh_token);
                    if (IdPSessionSecret == null)
                        return null;
                    AccessTokenEntry = (AccessTokenEntry)AccessTokenRecs.getEntry(IdPSessionSecret, req.client_id);
                    AccessTokenEntry newAccessTokenEntry = createAccessTokenEntry(AccessTokenEntry.redirect_uri, AccessTokenEntry.scope, AccessTokenEntry.state);
                    if (AccessTokenRecs.setEntry(newAccessTokenEntry.access_token, req.client_id, newAccessTokenEntry) == false)
                        return null;
                    resp.access_token = AccessTokenEntry.access_token;
                    resp.refresh_token = AccessTokenEntry.refresh_token;
                    return resp;
                default:
                    return null;
            }
        }
        public abstract AuthorizationCodeEntry createAuthorizationCodeEntry(AuthorizationRequest req);
        public abstract AccessTokenEntry createAccessTokenEntry(string redirect_uri, string scope, string state);
    }

}
