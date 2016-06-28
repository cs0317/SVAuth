using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Reflection;

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
        // serialization? ~ t-mattmc@microsoft.com 2016-06-01
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
       /* public AccessTokenResponse(AccessTokenResponse srcObj = null)
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
        }*/
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

    //The data strctures of AuthorizationCodeEntry and AccessTokenEntry are the same, but the procedures handling them are different.
    public class AuthorizationCodeEntry
    {
        public string IdPSessionSecret;
        public string client_id;
        public string scope;
    }

    public class AccessTokenEntry
    {
        public string IdPSessionSecret;
        public string client_id;
        public string scope;
    }

    public abstract class ID_Claim : GenericAuth.ID_Claim
    {
        string redirect_uri;
        public override string Redir_dest
        {
            get { return redirect_uri; }
        }
    }
    /*
    public interface AuthorizationCodeRecs : GenericAuth.IdPAuthRecords_Base
    {
        string findISSByClientIDAndCode(string client_id, string authorization_code);
    }

    public interface AccessTokenRecs : GenericAuth.IdPAuthRecords_Base
    {
        string findISSByClientIDAndAccessToken(string client_id, string access_token);
        string findISSByClientIDAndRefreshToken(string client_id, string refresh_token);
    }
    */
    // For interim use testing SVX_OPS.  Obviously this won't pass verification.
    // ~ t-mattmc@microsoft.com 2016-06-07
    public class DummyConcreteAuthorizationServer : GenericAuth.AS
    {
        public SVX.SVX_MSG DummyGetAccessToken(SVX.SVX_MSG input)
        {
            return new SVX.SVX_MSG();
        }
        public SVX.SVX_MSG DummyGetUserProfile(SVX.SVX_MSG input)
        {
            return new SVX.SVX_MSG();
        }

        public override GenericAuth.ID_Claim Process_SignInIdP_req(GenericAuth.SignInIdP_Req req)
        {
            throw new NotImplementedException();
        }

        public override GenericAuth.SignInIdP_Resp_SignInRP_Req Redir(string dest, GenericAuth.ID_Claim _ID_Claim)
        {
            throw new NotImplementedException();
        }
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
        public string redirect_uri;
        public override string Domain
        {
            get { return redirect_uri; }
            set { redirect_uri = value; }
        }
        // Why are the parameters optional?  I don't see how this class can work without them. ~ t-mattmc@microsoft.com 2016-05-31
        public Client(string client_id1 = null, string redierct_uri1 = null, string client_secret1 = null, string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null)
        {
            client_id = client_id1;
            redirect_uri = redierct_uri1;
            client_secret = client_secret1;
            AuthorizationEndpointUrl = AuthorizationEndpointUrl1;
            TokenEndpointUrl = TokenEndpointUrl1;
        }

        protected abstract Type ModelAuthorizationServerType { get; }
        // Get the content for Program.cs in the VProgram.
        protected abstract string VProgramMainContent { get; }

        /*** Methods about AuthorizationRequest ***/
        public abstract AuthorizationRequest createAuthorizationRequest(SVX.SVX_MSG inputMSG);
        public AuthorizationRequest _createAuthorizationRequest(SVX.SVX_MSG inputMSG)
        {
            var outputMSG = createAuthorizationRequest(inputMSG);
            SVX.SVX_Ops.recordme(this, inputMSG, outputMSG);
            return outputMSG;
        }
        public abstract string /*Uri*/ marshalCreateAuthorizationRequest(AuthorizationRequest _AuthorizationRequest);

        /*** Methods about AccessTokenRequest ***/
        protected virtual Type LoginCallbackRequestType { get { return typeof(AuthorizationResponse); } }
        public abstract AccessTokenRequest createAccessTokenRequest(SVX.SVX_MSG inputMSG);
        public AccessTokenRequest _createAccessTokenRequest(SVX.SVX_MSG inputMSG)
        {
            var outputMSG = this.createAccessTokenRequest(inputMSG);
            SVX.SVX_Ops.recordme(this, inputMSG, outputMSG);
            return outputMSG;
        }
        public abstract HttpRequestMessage marshalCreateAccessTokenRequest(AccessTokenRequest _AccessTokenRequest);

        /*** Methods about UserProfileRequest ***/
        protected virtual Type AccessTokenResponseType { get { return typeof(AccessTokenResponse); } }
        public abstract UserProfileRequest createUserProfileRequest(SVX.SVX_MSG inputMSG);
        public UserProfileRequest _createUserProfileRequest(SVX.SVX_MSG inputMSG)
        {
            var outputMSG = this.createUserProfileRequest(inputMSG);
            // The input is the AccessTokenResponse, which is server-to-server.
            SVX.SVX_Ops.recordme(this, inputMSG, outputMSG, false, true);
            return outputMSG;
        }
        public abstract HttpRequestMessage marshalCreateUserProfileRequest(UserProfileRequest _UserProfileRequest);

        /*** Methods about Conclusion ***/
        protected virtual Type UserProfileResponseType { get { return typeof(UserProfileResponse); } }
        public abstract GenericAuth.AuthenticationConclusion createConclusion(SVX.SVX_MSG inputMSG);
        public GenericAuth.AuthenticationConclusion _createConclusion(SVX.SVX_MSG inputMSG)
        {
            var outputMSG = this.createConclusion(inputMSG);
            // The input is the UserProfileResponse, which is server-to-server.
            //
            // The conclusion is consumed locally.  I think treating it as
            // signed will give the right result. ~ t-mattmc@microsoft.com 2016-06-06
            SVX.SVX_Ops.recordme(this, inputMSG, outputMSG, true, true);
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
            // ~ t-mattmc@microsoft.com 2016-06-01
            SVX.SVX_MSG inputMSG = (SVX.SVX_MSG)Utils.ObjectFromQuery(
                context.Request.Query, LoginCallbackRequestType);
            var _AccessTokenRequest = _createAccessTokenRequest(inputMSG);
            var rawReq = marshalCreateAccessTokenRequest(_AccessTokenRequest);
            var RawAccessTokenResponse = await SVX.Utils.PerformHttpRequestAsync(rawReq);
            Trace.Write("Got AccessTokenResponse");

            SVX.SVX_MSG inputMSG2 = (SVX.SVX_MSG)JsonConvert.DeserializeObject(
                Utils.ReadContent(RawAccessTokenResponse.Content), AccessTokenResponseType);
            // TODO: Figure out the correct receiver and method name.
            SVX.SVX_Ops.recordCustom(ModelAuthorizationServerType, _AccessTokenRequest, inputMSG2,
                nameof(AuthorizationServer.TokenEndpoint), "AS", false, false);
            var _UserProfileRequest = _createUserProfileRequest(inputMSG2);
            var rawReq2 = marshalCreateUserProfileRequest(_UserProfileRequest);
            var RawUserProfileResponse = await SVX.Utils.PerformHttpRequestAsync(rawReq2);
            Trace.Write("Got UserProfileResponse");

            SVX.SVX_MSG inputMSG3 = (SVX.SVX_MSG)JsonConvert.DeserializeObject(
                Utils.ReadContent(RawUserProfileResponse.Content), UserProfileResponseType);
            SVX.SVX_Ops.recordCustom(ModelAuthorizationServerType, _UserProfileRequest, inputMSG3,
                nameof(AuthorizationServer.UserProfileEndpoint), "AS", false, false);
            var conclusion = _createConclusion(inputMSG3);

            SVX.VProgramGenerator.Program_cs = VProgramMainContent;
            await AuthenticationDone(conclusion, context);
        }
    }

    public abstract class AuthorizationServer : GenericAuth.AS
    {
        static NondetOAuth20 NondetOAuth20;
        public Dictionary<string, AuthorizationCodeEntry> AuthorizationCodes = new Dictionary<string, AuthorizationCodeEntry>();
        public Dictionary<string, AccessTokenEntry> AccessTokens = new Dictionary<string, AccessTokenEntry>();
        public AuthorizationServer()
        {
            AuthorizationCodes[NondetOAuth20.String()] = NondetOAuth20.AuthorizationCodeEntry();
        }
       public override GenericAuth.ID_Claim Process_SignInIdP_req(GenericAuth.SignInIdP_Req req1)
        {
            AuthorizationRequest req = (AuthorizationRequest)req1;
            switch (req.response_type)
            {
                case "code":
                    return get_ID_Claim_From_Authorization_Request(req);
                default:
                    return null;
            }
        }

        virtual public AccessTokenResponse TokenEndpoint(SVX.SVX_MSG req1)
        {
           //System.Diagnostics.Contracts.Contract.Assert(false);
            AuthorizationCodeEntry AuthorizationCodeEntry;
            AccessTokenRequest req = (AccessTokenRequest)req1;
            if (req == null) return null;
            //System.Diagnostics.Contracts.Contract.Assert(false);
            AccessTokenResponse resp = new AccessTokenResponse();
            //SVX_Ops.recordme(this, req, resp);
            switch (req.grant_type)
            {
                case "authorization_code":
                    AuthorizationCodeEntry = AuthorizationCodes[req.code];
                    if (AuthorizationCodeEntry == null)
                        return null;
                    if (AuthorizationCodeEntry.client_id != req.client_id)
                        return null;
                    if (IdentityRecords.getEntry(AuthorizationCodeEntry.IdPSessionSecret, AuthorizationCodeEntry.client_id).Redir_dest
                            != req.redirect_uri)
                        return null;
                    string AccessToken = createAccessToken(AuthorizationCodeEntry);
                    resp.access_token = AccessToken;
                    resp.refresh_token = "access_token";
                    resp.expires_in = "";
                    resp.refresh_token = null;
                    return resp;
                case "refresh_token":
                    return null;
                default:
                    return null;
            }
        }

        public UserProfileResponse UserProfileEndpoint(SVX.SVX_MSG req1)
        {

            UserProfileRequest req = (UserProfileRequest)req1;
            if (req == null) return null;
            AccessTokenEntry AccessTokenEntry = AccessTokens[req.access_token];
            if (AccessTokenEntry == null) return null;

            //SVX_Ops.recordme(this, req, resp);
            return createUserProfileResponse((OAuth20.ID_Claim)IdentityRecords.getEntry(AccessTokenEntry.IdPSessionSecret,AccessTokenEntry.client_id));
        }
        public abstract ID_Claim get_ID_Claim_From_Authorization_Request(AuthorizationRequest req);
        public abstract string createAccessToken(AuthorizationCodeEntry AuthorizationCodeEntry);
        public abstract UserProfileResponse createUserProfileResponse(ID_Claim ID_Claim);
    }

    public interface NondetOAuth20 : GenericAuth.Nondet_Base
    {
        int Int();
        string String();
        bool Bool();
        SVX.SVX_MSG SVX_MSG();
        AuthorizationCodeEntry AuthorizationCodeEntry();
    }
}
