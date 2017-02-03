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
using System.Diagnostics.Contracts;
using System.Security.Cryptography;
using System.Text;

namespace SVAuth.OAuth20
{
    static class OAuth20Standards
    {
        public static SVX.Principal OAuthClientIDPrincipal(SVX.Principal idpPrincipal, string clientID) =>
          SVX.Principal.Of(idpPrincipal.name + ":" + clientID);
    }

    /***********************************************************/
    /*               Messages between parties                  */
    /***********************************************************/

    public class AuthorizationRequest : SVX.SVX_MSG
    {
        public string response_type;
        public string client_id;
        public string redirect_uri;
        public string scope;
        public SVX.Secret state;
    }

    public class AuthorizationResponse : SVX.SVX_MSG
    {
        public SVX.Secret code;
        public SVX.Secret state;
    }

    public class AuthorizationErrorResponse : SVX.SVX_MSG
    {
        protected string error;
        protected string error_description = null;
        protected string error_uri = null;
        protected string state = null;
    }

    public class AccessTokenRequest : SVX.SVX_MSG
    {
        public string grant_type;
        public SVX.Secret code;
        public string redirect_uri;
        public string client_id;
        // Currently we do not model client_secret as an SVX secret because we
        // do not need to reason about its secrecy.  We could still use an SVX
        // secret if we wanted to make it harder to accidentally leak.
        public string client_secret;
        public string refresh_token = null;
    }

    public class AccessTokenResponse : SVX.SVX_MSG
    {
        // Same remark as client_secret.
        public string access_token;
        public string token_type;
        public string expires_in;
        public string refresh_token = null;
    }

    public class UserProfileRequest : SVX.SVX_MSG
    {
        public string fields;
        public string access_token;
    }
    public class UserProfileResponse : SVX.SVX_MSG
    {
    }

    [BCTOmit]
    public class MessageStructures
    {
        // In many cases, we'll actually be using service-provider-specific
        // message subclasses.  SVX will let us get away with this as long as
        // the subclasses do not add any new secrets.  Maybe SVX should be
        // stricter, but at the moment that would just cost us a lot of
        // boilerplate for no practical benefit.
        public readonly SVX.MessageStructure<AuthorizationRequest> authorizationRequest;
        public readonly SVX.MessageStructure<AuthorizationResponse> authorizationResponse;
        public readonly SVX.MessageStructure<AccessTokenRequest> accessTokenRequest;
        public readonly SVX.MessageStructure<AccessTokenResponse> accessTokenResponse;
        public readonly SVX.MessageStructure<UserProfileRequest> userProfileRequest;
        public readonly SVX.MessageStructure<UserProfileResponse> userProfileResponse;

        public MessageStructures(SVX.Principal idpPrincipal)
        {
            authorizationRequest = new SVX.MessageStructure<AuthorizationRequest> { BrowserOnly = true };
            authorizationRequest.AddSecret(nameof(AuthorizationRequest.state),
                (msg) => new SVX.PrincipalHandle[] { GenericAuth.GenericAuthStandards.GetUrlTargetPrincipal(msg.redirect_uri) });

            authorizationResponse = new SVX.MessageStructure<AuthorizationResponse> { BrowserOnly = true };
            authorizationResponse.AddSecret(nameof(AuthorizationResponse.state),
                (msg) => new SVX.PrincipalHandle[] { });
            authorizationResponse.AddSecret(nameof(AuthorizationResponse.code),
                (msg) => new SVX.PrincipalHandle[] { idpPrincipal });

            accessTokenRequest = new SVX.MessageStructure<AccessTokenRequest>();
            accessTokenRequest.AddSecret(nameof(AccessTokenRequest.code),
                (msg) => new SVX.PrincipalHandle[] { });

            accessTokenResponse = new SVX.MessageStructure<AccessTokenResponse>();

            userProfileRequest = new SVX.MessageStructure<UserProfileRequest>();
            userProfileResponse = new SVX.MessageStructure<UserProfileResponse>();
        }
    }

    /***********************************************************/
    /*                          Parties                        */
    /***********************************************************/

    class StateParams
    {
        // Set an arbitrary fixed order to try to make sure the serialized form
        // is reproducible.  It would matter in the middle of an upgrade of a
        // replicated RP to a new .NET version that changes the field order
        // returned by reflection.  Are there other reproducibility issues with
        // Json.NET?

        // We expect this to be a facet issued by the RP.
        [JsonProperty(Order = 0)]
        public SVX.PrincipalHandle client;

        [JsonProperty(Order = 1)]
        public SVX.Principal idpPrincipal;
    }

    // This class demonstrates how to use an HMAC, which is the easiest,
    // especially for a replicated RP.  It might be better to use a dictionary
    // (or an external key-value store) to enforce that each state is used only
    // once and enforce an expiration time, etc.
    class StateGenerator : SVX.SecretGenerator<StateParams>
    {
        readonly SVX.Principal rpPrincipal;
        readonly string key;

        // TODO: Get the key lazily once SVX supports the "prod context".
        internal StateGenerator(SVX.Principal rpPrincipal, string key)
        {
            this.rpPrincipal = rpPrincipal;
            this.key = key;
        }

        protected override SVX.PrincipalHandle[] GetReaders(object theParams)
        {
            var params2 = (StateParams)theParams;
            return new SVX.PrincipalHandle[] { params2.idpPrincipal, rpPrincipal, params2.client };
        }

        protected override string RawGenerate(StateParams theParams)
        {
            return Utils.Hmac(JsonConvert.SerializeObject(theParams), key);
        }

        protected override void RawVerify(StateParams theParams, string secretValue)
        {
            if (secretValue != RawGenerate(theParams))
                throw new ArgumentException();
        }
    }

    public abstract class Client : GenericAuth.RP
    {
        // Lazy to avoid running initialization code in the vProgram.
        MessageStructures messageStructures_;
        MessageStructures messageStructures
        {
            get
            {
                if (messageStructures_ == null)
                    messageStructures_ = new MessageStructures(idpParticipantId.principal);
                return messageStructures_;
            }
        }

        public string client_id;
        public string client_secret;
        public string TokenEndpointUrl;
        public string AuthorizationEndpointUrl;
        public string redirect_uri;
        internal StateGenerator stateGenerator;

        // Why are the parameters optional?  I don't see how this class can work without them. ~ t-mattmc@microsoft.com 2016-05-31
        public Client(SVX.Principal rpPrincipal,
            string client_id1 = null, string redierct_uri1 = null, string client_secret1 = null,
            string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null,
            string stateKey = null)
            : base(rpPrincipal)
        {
            // Give this a valid value in the vProgram.  FIXME: Doing observably
            // different things in the vProgram is unsound if we aren't careful
            // and poor practice in general.  Once SVX supports passing
            // configuration other than just a principal, use that instead.
            if (redierct_uri1 == null)
                redierct_uri1 = $"https://{rpPrincipal.name}/dummy";

            // Ditto for client_id.
            if (client_id1 == null)
                client_id1 = "dummy:" + rpPrincipal.name;

            client_id = client_id1;
            redirect_uri = redierct_uri1;
            client_secret = client_secret1;
            AuthorizationEndpointUrl = AuthorizationEndpointUrl1;
            TokenEndpointUrl = TokenEndpointUrl1;

            // This will allow the state to be exported in prod and will be
            // reached in the vProgram to know that the redirect_uri principal
            // is a trusted server.
            SVX.VProgram_API.AssumeActsFor(GenericAuth.GenericAuthStandards.GetUrlTargetPrincipal(redirect_uri), rpPrincipal);

            SVX.VProgram_API.AssumeActsFor(OAuth20Standards.OAuthClientIDPrincipal(idpParticipantId.principal, client_id), rpPrincipal);

            stateGenerator = new StateGenerator(rpPrincipal, stateKey);
        }

        protected abstract ModelAuthorizationServer CreateModelAuthorizationServer();

        // This is a little arbitrary.  When we sort out how to pass
        // configuration to participants, it would be a good opportunity to get
        // rid of this.
        protected override SVX.ParticipantId idpParticipantId =>
            SVX.ParticipantId.Of(CreateModelAuthorizationServer());

        /*** Methods about AuthorizationRequest ***/
        public abstract AuthorizationRequest createAuthorizationRequest(SVX.PrincipalFacet client);
        public abstract string /*Uri*/ marshalAuthorizationRequest(AuthorizationRequest authorizationRequest);

        /*** Methods about AccessTokenRequest ***/
        protected virtual Type LoginCallbackRequestType { get { return typeof(AuthorizationResponse); } }
        public virtual AccessTokenRequest createAccessTokenRequest(AuthorizationResponse authorizationResponse) { return null; }
        public virtual HttpRequestMessage marshalAccessTokenRequest(AccessTokenRequest accessTokenRequest) { return null; }

        /*** Methods about UserProfileRequest ***/
        protected virtual Type AccessTokenResponseType { get { return typeof(AccessTokenResponse); } }
        public virtual UserProfileRequest createUserProfileRequest(AccessTokenResponse accessTokenResponse) { return null; }
        public virtual HttpRequestMessage marshalUserProfileRequest(UserProfileRequest userProfileRequest) { return null; }

        /*** Methods about Conclusion ***/
        protected virtual Type UserProfileResponseType { get { return typeof(UserProfileResponse); } }
        // conclusion.authenticatedClient should be set to authorizationResponse.SVX_sender.
        // The arguments must be passed in this order for SVX to detect that
        // userProfileResponse resulted from a computation on authorizationResponse.
        public virtual GenericAuth.AuthenticationConclusion createConclusion(
            AuthorizationResponse authorizationResponse, UserProfileResponse userProfileResponse) { return null; }

        /*************** Start defining OAuth flows ************************/
        public Task Login_StartAsync(HttpContext httpContext)
        {
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);

            // The SymT doesn't actually get used, but why not.
            var _AuthorizationRequest = SVX.SVX_Ops.Call(createAuthorizationRequest, context.client);

            // NOTE: We are assuming that the target URL used by
            // marshalAuthorizationRequest belongs to the principal
            // idpParticipantId.principal.  We haven't extended SVX enforcement
            // that far yet.
            messageStructures.authorizationRequest.Export(_AuthorizationRequest, context.client, idpParticipantId.principal);
            var rawReq = marshalAuthorizationRequest(_AuthorizationRequest);

            //set the referrer in the CurrentUrl cookie
            try
            {
                Microsoft.Extensions.Primitives.StringValues referer;
                if (context.http.Request.Headers.TryGetValue("referer", out referer))
                {
                    context.http.Response.Headers["set-cookie"] = Microsoft.Extensions.Primitives.StringValues.Concat
                            (context.http.Response.Headers["set-cookie"], "LoginPageUrl=" + System.Net.WebUtility.UrlDecode(referer) + ";path=/");
                }
            }
            catch (Exception ex)
            {
                //there is already a set-cookie for LoginPageUrl
            };
            context.http.Response.StatusCode = 303;
            context.http.Response.Redirect(rawReq);

            return Task.CompletedTask;
        }
        public virtual async Task AuthorizationCodeFlow_Login_CallbackAsync(HttpContext httpContext)
        {
            Trace.Write("AuthorizationCodeFlow_Login_CallbackAsync");
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);
            var idp = CreateModelAuthorizationServer();

            // See if any subclasses need us to use their special
            // AuthorizationRequest subclass.
            var dummyAuthorizationRequest = new AuthorizationRequest();

            // This design is following the original Auth.JS as closely as
            // possible.  Arguably, we should give concrete subclasses full
            // control of unmarshalling, just like marshalling.  The original
            // parseHttpMessage supports both requests (query) and responses,
            // but here we know which is which.
            // ~ t-mattmc@microsoft.com 2016-06-01
            var authorizationResponse = (AuthorizationResponse)Utils.ObjectFromQuery(
                context.http.Request.Query, LoginCallbackRequestType);

            messageStructures.authorizationResponse.ImportWithModel(authorizationResponse,
                () => { idp.FakeCodeEndpoint(dummyAuthorizationRequest, authorizationResponse); },
                SVX.PrincipalFacet.GenerateNew(SVX_Principal),  // unknown producer
                context.client);

            var accessTokenRequest = SVX.SVX_Ops.Call(createAccessTokenRequest, authorizationResponse);

            messageStructures.accessTokenRequest.Export(accessTokenRequest, idp.SVX_Principal, null);
            var rawAccessTokenRequest = marshalAccessTokenRequest(accessTokenRequest);
            var rawAccessTokenResponse = await Utils.PerformHttpRequestAsync(rawAccessTokenRequest);

            Trace.Write("Got AccessTokenResponse");

            var accessTokenResponse = (AccessTokenResponse)JsonConvert.DeserializeObject(
                Utils.ReadContent(rawAccessTokenResponse.Content), AccessTokenResponseType);
            messageStructures.accessTokenResponse.ImportDirectResponseWithModel(accessTokenResponse,
                () => { idp.FakeTokenEndpoint(accessTokenRequest, accessTokenResponse); },
                idp.SVX_Principal, SVX_Principal);

            var userProfileRequest = SVX.SVX_Ops.Call(createUserProfileRequest, accessTokenResponse);

            messageStructures.userProfileRequest.Export(userProfileRequest, idp.SVX_Principal, null);
            var rawUserProfileRequest = marshalUserProfileRequest(userProfileRequest);
            var rawUserProfileResponse = await Utils.PerformHttpRequestAsync(rawUserProfileRequest);
            Trace.Write("Got UserProfileResponse");
            var userProfileResponse = (UserProfileResponse)JsonConvert.DeserializeObject(
                Utils.ReadContent(rawUserProfileResponse.Content), UserProfileResponseType);
            messageStructures.userProfileResponse.ImportDirectResponseWithModel(userProfileResponse,
                () => { idp.FakeUserProfileEndpoint(userProfileRequest, userProfileResponse); },
                idp.SVX_Principal, SVX_Principal);

            var conclusion = SVX.SVX_Ops.Call(createConclusion, authorizationResponse, userProfileResponse);

            await AuthenticationDone(conclusion, context);
        }
    }

    public class AuthorizationCodeParams
    {
        public string userID;
        public string redirect_uri;
    }

    public class AuthorizationCodeGenerator : SVX.SecretGenerator<AuthorizationCodeParams>
    {
        readonly SVX.Principal idpPrincipal;

        // Since this isn't a MessagePayloadSecretGenerator used with "verify on
        // import", we don't have to worry about it having a default constructor
        // for the time being, so we can do this, which leaves a little less
        // boilerplate in concrete model IdPs than subclassing
        // AuthorizationCodeGenerator and overriding a propertly.
        public AuthorizationCodeGenerator(SVX.Principal idpPrincipal)
        {
            this.idpPrincipal = idpPrincipal;
        }

        protected override SVX.PrincipalHandle[] GetReaders(object theParams)
        {
            var params2 = (AuthorizationCodeParams)theParams;
            return new SVX.Principal[] {
                idpPrincipal,
                GenericAuth.GenericAuthStandards.GetUrlTargetPrincipal(params2.redirect_uri),
                GenericAuth.GenericAuthStandards.GetIdPUserPrincipal(idpPrincipal, params2.userID),
            };
        }

        // Generate and Verify are called only by model IdP methods that are
        // executed only in the vProgram, so these are not reached.

        protected override string RawGenerate(AuthorizationCodeParams theParams)
        {
            throw new NotImplementedException();
        }

        protected override void RawVerify(AuthorizationCodeParams theParams, string secretValue)
        {
            throw new NotImplementedException();
        }
    }

    public class AccessTokenParams
    {
        public string userID;
    }

    public class AccessTokenGenerator : SVX.TokenGenerator<AccessTokenParams>
    {
        // Ditto AuthorizationCodeGenerator.

        protected override string RawGenerate(AccessTokenParams theParams)
        {
            throw new NotImplementedException();
        }

        protected override void RawVerify(AccessTokenParams theParams, string tokenValue)
        {
            throw new NotImplementedException();
        }
    }

    // This class is not designed at this point to serve as a base for real
    // authorization server implementations.
    public abstract class ModelAuthorizationServer : GenericAuth.AS
    {
        // Make members overridable on first need...

        // Lazy to avoid running initialization code in the vProgram.
        MessageStructures messageStructures_;
        MessageStructures messageStructures
        {
            get
            {
                if (messageStructures_ == null)
                    messageStructures_ = new MessageStructures(SVX_Principal);
                return messageStructures_;
            }
        }

        readonly AuthorizationCodeGenerator authorizationCodeGenerator;
        readonly AccessTokenGenerator accessTokenGenerator = new AccessTokenGenerator();

        public ModelAuthorizationServer(SVX.Principal idpPrincipal)
            : base(idpPrincipal)
        {
            // Initialization order restriction
            authorizationCodeGenerator = new AuthorizationCodeGenerator(SVX_Principal);
        }

        public class IdPAuthenticationEntry : SVX.SVX_MSG
        {
            public SVX.PrincipalHandle authenticatedClient;
            public string userID;
        }

        public void FakeCodeEndpoint(AuthorizationRequest req, AuthorizationResponse resp)
        {
            // XXX: Do we need to check that req.response_type == "code"?
            // Currently, as per the comment in
            // AuthorizationCodeFlow_Login_CallbackAsync, FakeCodeEndpoint only
            // needs to handle the kinds of requests actually made by RP, which
            // request a code.  We don't care about the value of
            // req.response_type in its own right.

            var producer = SVX.PrincipalFacet.GenerateNew(SVX_Principal);
            var client = SVX.PrincipalFacet.GenerateNew(SVX_Principal);

            messageStructures.authorizationRequest.FakeImport(req, producer, client);

            var idpConc = new IdPAuthenticationEntry();  // Nondet
            SVX.SVX_Ops.FakeCall(SVX_ConcludeClientAuthentication, idpConc, idpConc);

            SVX.SVX_Ops.FakeCall(SVX_MakeAuthorizationResponse, req, idpConc, resp);

            messageStructures.authorizationResponse.FakeExport(resp);
        }

        // Write lambda by hand because all compiler-generated classes are
        // currently excluded from decompilation of method bodies by CCI.
        class SignedInDeclarer
        {
            internal ModelAuthorizationServer outer;
            internal IdPAuthenticationEntry entry;
            internal void Declare()
            {
                outer.SignedInPredicate.Declare(SVX.VProgram_API.UnderlyingPrincipal(entry.authenticatedClient), entry.userID);
            }
        }

        public IdPAuthenticationEntry SVX_ConcludeClientAuthentication(IdPAuthenticationEntry entry)
        {
            var d = new SignedInDeclarer { outer = this, entry = entry };
            SVX.SVX_Ops.Ghost(d.Declare);
            SVX.VProgram_API.AssumeActsFor(entry.authenticatedClient,
                GenericAuth.GenericAuthStandards.GetIdPUserPrincipal(SVX_Principal, entry.userID));
            // Reuse the message... Should be able to get away with it.
            return entry;
        }

        public AuthorizationResponse SVX_MakeAuthorizationResponse(AuthorizationRequest req, IdPAuthenticationEntry idpConc)
        {
            // In the real CodeEndpoint, we would request an
            // IdPAuthenticationEntry for req.SVX_sender, but SVX doesn't know
            // that, so we have to do a concrete check.
            SVX.VProgram_API.Assert(req.SVX_sender == idpConc.authenticatedClient);

            // Copy/paste: [With this expression inlined below, BCT silently mistranslated the code.]
            var theParams = new AuthorizationCodeParams
            {
                redirect_uri = req.redirect_uri,
                userID = idpConc.userID
            };
            var authorizationCode = authorizationCodeGenerator.Generate(theParams, SVX_Principal);

            return new AuthorizationResponse
            {
                code = authorizationCode,
                state = req.state
            };
        }

        public void FakeTokenEndpoint(AccessTokenRequest req, AccessTokenResponse resp)
        {
            // XXX: Anything we can do about this boilerplate?
            var producer = SVX.PrincipalFacet.GenerateNew(SVX_Principal);
            var client = SVX.PrincipalFacet.GenerateNew(SVX_Principal);

            messageStructures.accessTokenRequest.FakeImport(req, producer, client);
            SVX.SVX_Ops.FakeCall(SVX_MakeAccessTokenResponse, req, (AuthorizationCodeParams)null, resp);
            messageStructures.accessTokenResponse.FakeExportDirectResponse(resp, producer);
        }

        public virtual AccessTokenResponse SVX_MakeAccessTokenResponse(AccessTokenRequest req, AuthorizationCodeParams codeParamsHint)
        {
            // We should only get here with req.grant_type ==
            // "authorization_code", so we don't have to worry about modeling
            // what IdP does in any other case.
            if (req.grant_type != "authorization_code")
                return SVX.VProgram_API.Nondet<AccessTokenResponse>();

            authorizationCodeGenerator.Verify(codeParamsHint, req.code);

            if (req.redirect_uri != codeParamsHint.redirect_uri)
                throw new Exception("Authorization code RP mismatch");

            var tokenParams = new AccessTokenParams
            {
                userID = codeParamsHint.userID
            };
            var token = accessTokenGenerator.Generate(tokenParams);
            return new AccessTokenResponse
            {
                access_token = token
            };
        }

        public void FakeUserProfileEndpoint(UserProfileRequest req, UserProfileResponse resp)
        {
            var producer = SVX.PrincipalFacet.GenerateNew(SVX_Principal);
            var client = SVX.PrincipalFacet.GenerateNew(SVX_Principal);

            messageStructures.userProfileRequest.FakeImport(req, producer, client);
            SVX.SVX_Ops.FakeCall(SVX_MakeUserProfileResponse, req, (AccessTokenParams)null, resp);
            messageStructures.userProfileResponse.FakeExportDirectResponse(resp, producer);
        }

        public abstract UserProfileResponse CreateUserProfileResponse(string userID);

        public UserProfileResponse SVX_MakeUserProfileResponse(UserProfileRequest req, AccessTokenParams tokenParamsHint)
        {
            accessTokenGenerator.Verify(tokenParamsHint, req.access_token);
            return CreateUserProfileResponse(tokenParamsHint.userID);
        }

    }

}
