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
using JwtCore;
using SVAuth.OAuth20;
using SVX;

namespace SVAuth.OIDC10
{

    /***********************************************************/
    /*               Messages between parties                  */
    /***********************************************************/

    public class AuthenticationRequest : OAuth20.AuthorizationRequest
    {
        public string response_mode = null;
        public string nonce = null;
        public string display = null;
        public string prompt = null;
        public string max_age = null;
        public string ui_locales = null;
        public string id_token_hint = null;
        public string login_hint = null;
        public string acr_values = null;
    }

    public class AuthenticationResponse_with_id_token : OAuth20.AuthorizationResponse
    {
        public string access_token;
        public SVX.PayloadSecret<JwtTokenBody> id_token;
    }

    public class JwtTokenBody : SVX_MSG
    {
        public string aud, iss, exp, sub;
    }

    public abstract class OIDCTokenVerifier : MessagePayloadSecretGenerator<JwtTokenBody>
    {

        public Principal IdPPrincipal;

        protected override PrincipalHandle Signer => IdPPrincipal;

        // XXX Eventually this needs to be a parameter.
        protected override PrincipalHandle[] GetReaders(object theParams)
        {
            var body = (JwtTokenBody)theParams;
            return new PrincipalHandle[] {
                    // Comment this to get an internal error during secret generation.
                    Signer,
                    // Comment either of these to see the secret export check fail.
                    OAuth20Standards.OAuthClientIDPrincipal(IdPPrincipal, body.aud),
                    GenericAuth.GenericAuthStandards.GetIdPUserPrincipal(IdPPrincipal, body.sub),
                    // Uncomment to see the verification fail.
                    //Principal.Of("other")
                };
        }

        public abstract JwtTokenBody UnReflectJwtTokenBody(JObject obj);
        protected override JwtTokenBody RawExtractUnverified(string secretValue)
        {
            JObject id_token = JObject.Parse(JwtCore.JsonWebToken.Decode(secretValue, "", false));
            return UnReflectJwtTokenBody(id_token);
        }

        protected override string RawGenerate(JwtTokenBody theParams)
        {
            throw new NotImplementedException();
        }
     
    }


    [BCTOmit]
    abstract public class MessageStructures: OAuth20.MessageStructures
    {
        public readonly SVX.MessageStructure<AuthenticationResponse_with_id_token> authenticationResponse_with_id_token;
        public readonly SVX.MessageStructure<TokenResponse> tokenResponse;
        protected abstract OIDCTokenVerifier getTokenVerifier();
        public MessageStructures(SVX.Principal idpPrincipal) : base(idpPrincipal)
        {
            authenticationResponse_with_id_token = new SVX.MessageStructure<AuthenticationResponse_with_id_token> { BrowserOnly = true };
            authenticationResponse_with_id_token.AddMessagePayloadSecret(nameof(AuthenticationResponse_with_id_token.id_token),
                (msg) => new SVX.PrincipalHandle[] { },
                getTokenVerifier(),
                true);
            authenticationResponse_with_id_token.AddSecret(nameof(AuthenticationResponse_with_id_token.state),
               (msg) => new SVX.PrincipalHandle[] { });

            tokenResponse = new SVX.MessageStructure<TokenResponse>();
            tokenResponse.AddMessagePayloadSecret(nameof(TokenResponse.id_token),
                (msg) => new SVX.PrincipalHandle[] { },
                getTokenVerifier(),
                false);
        }
    }

    public class TokenResponse : OAuth20.AccessTokenResponse
    {
        public SVX.PayloadSecret<JwtTokenBody> id_token;
    }

    public abstract class RelyingParty : OAuth20.Client
    {
        public RelyingParty(SVX.Principal rpPrincipal, string client_id1, string redierct_uri1, string client_secret1, 
            string AuthorizationEndpointUrl1, string TokenEndpointUrl1, string stateKey = null)
            : base(rpPrincipal, client_id1, redierct_uri1, client_secret1, AuthorizationEndpointUrl1, TokenEndpointUrl1, stateKey)
        {
        }

        protected override ModelAuthorizationServer CreateModelAuthorizationServer() 
        {
            // SVX verification is not implemented yet.
            throw new NotImplementedException();
        }

        protected sealed override SVX.ParticipantId idpParticipantId =>
           SVX.ParticipantId.Of(CreateModelOIDCAuthenticationServer());

        abstract protected ModelOIDCAuthenticationServer CreateModelOIDCAuthenticationServer();
        //protected abstract void set_parse_id_token(SVX.SVX_MSG msg, JObject id_token);

        // Use a different name: SVX is not guaranteed to handle method overloading.
        public virtual GenericAuth.AuthenticationConclusion createConclusionOidc(
            AuthorizationResponse authenticationResponse, TokenResponse tokenResponse) { return null; }

        public abstract MessageStructures GetMessageStructures();
        public override async Task AuthorizationCodeFlow_Login_CallbackAsync(HttpContext httpContext)
        {
            var idp = CreateModelOIDCAuthenticationServer();
            Trace.Write("AuthorizationCodeFlow_Login_CallbackAsync");
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);

            var authenticationResponse = (OAuth20.AuthorizationResponse)Utils.ObjectFromFormPost(
                context.http.Request.Form,typeof(OAuth20.AuthorizationResponse));

            GetMessageStructures().authorizationResponse.Import(authenticationResponse,
                SVX.PrincipalFacet.GenerateNew(SVX_Principal),  // unknown producer
                context.client);

            var _AccessTokenRequest = SVX.SVX_Ops.Call(createAccessTokenRequest,authenticationResponse);
            GetMessageStructures().accessTokenRequest.Export(_AccessTokenRequest, idpParticipantId.principal, null);
            _AccessTokenRequest.SVX_serializeSymT = false;
            var rawReq = marshalAccessTokenRequest(_AccessTokenRequest);
            var RawAccessTokenResponse = await Utils.PerformHttpRequestAsync(rawReq);
           
            Trace.Write("Got AccessTokenResponse");

            JObject jObject = JObject.Parse(RawAccessTokenResponse.Content.ReadAsStringAsync().Result);
            TokenResponse tokenResponse = Utils.UnreflectObject<TokenResponse>(jObject);
            idp.FakeTokenEndpoint(_AccessTokenRequest, tokenResponse);
            GetMessageStructures().tokenResponse.ImportDirectResponse(tokenResponse,
                    idpParticipantId.principal,
                    SVX_Principal
                );
            
            var conclusion = SVX.SVX_Ops.Call(createConclusionOidc,authenticationResponse, tokenResponse);
            await AuthenticationDone(conclusion, context);
        }
       // public virtual bool verify_and_decode_ID_Token(AuthenticationResponse_with_id_token AuthenticationResponse) { return false; }
        public virtual GenericAuth.AuthenticationConclusion createConclusionOidcImplicit(
            AuthenticationResponse_with_id_token authenticationResponse) { return null; }
        public async Task ImplicitFlow_Login_CallbackAsync(HttpContext httpContext)
        {
            Trace.Write("ImplicitFlow_Login_CallbackAsync");
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);
            AuthenticationResponse_with_id_token authenticationResponse_with_id_token= (AuthenticationResponse_with_id_token)Utils.ObjectFromFormPost
                (context.http.Request.Form, typeof(AuthenticationResponse_with_id_token));;
            var idp = CreateModelOIDCAuthenticationServer();
            var dummyAuthorizationRequest = new AuthorizationRequest();
            idp.FakeImplicitFlowIDTokenEndpoint(dummyAuthorizationRequest, authenticationResponse_with_id_token);

            GetMessageStructures().authenticationResponse_with_id_token.Import(authenticationResponse_with_id_token,
                SVX.PrincipalFacet.GenerateNew(SVX_Principal),  // unknown producer
                context.client);
            Trace.Write("Got Valid AuthenticationResponse");

            GenericAuth.AuthenticationConclusion conclusion = SVX_Ops.Call(createConclusionOidcImplicit,authenticationResponse_with_id_token);
            if (conclusion == null)
            {
                context.http.Response.Redirect(context.http.Request.Cookies["LoginPageUrl"]);
                return;
            }

            await AuthenticationDone(conclusion, context);
        }
    }

    // This class is not designed at this point to serve as a base for real
    // authorization server implementations.
    public abstract class ModelOIDCAuthenticationServer : GenericAuth.AS
    {
        protected abstract MessageStructures getMessageStrctures();
        protected abstract OIDCTokenVerifier getTokenGenerator();

        // Make members overridable on first need...

        // Lazy to avoid running initialization code in the vProgram.
        MessageStructures messageStructures_;
        MessageStructures messageStructures
        {
            get
            {
                if (messageStructures_ == null)
                    messageStructures_ = getMessageStrctures();
                return messageStructures_;
            }
        }

        readonly AuthorizationCodeGenerator authorizationCodeGenerator;
        readonly AccessTokenGenerator accessTokenGenerator = new AccessTokenGenerator();

        public ModelOIDCAuthenticationServer(SVX.Principal idpPrincipal)
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

        public void FakeImplicitFlowIDTokenEndpoint(AuthorizationRequest req, AuthenticationResponse_with_id_token resp)
        {
            var producer = SVX.PrincipalFacet.GenerateNew(SVX_Principal);
            var client = SVX.PrincipalFacet.GenerateNew(SVX_Principal);

            messageStructures.authorizationRequest.FakeImport(req, producer, client);

            var idpConc = new IdPAuthenticationEntry();  // Nondet
            SVX.SVX_Ops.FakeCall(SVX_ConcludeClientAuthentication, idpConc, idpConc);
            
            SVX.SVX_Ops.FakeCall(SVX_MakeAuthorizationResponse_with_id_token, req, idpConc, resp);
            SVX.SVX_Ops.FakeCall(SVX_MakeJwtTokenBody, req, idpConc, resp.id_token.theParams);
            messageStructures.authenticationResponse_with_id_token.FakeExport(resp);
        }

        // Write lambda by hand because all compiler-generated classes are
        // currently excluded from decompilation of method bodies by CCI.
        class SignedInDeclarer
        {
            internal ModelOIDCAuthenticationServer outer;
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
        public JwtTokenBody SVX_MakeJwtTokenBody(AuthorizationRequest req, IdPAuthenticationEntry idpConc)
        {
            return MakeJwtTokenBody(req.client_id, idpConc.userID);
        }
        public JwtTokenBody MakeJwtTokenBody(string client_id, string userID)
        {
            return new JwtTokenBody
            {
                aud = client_id,
                iss = SVX.VProgram_API.Nondet<String>(),
                exp = SVX.VProgram_API.Nondet<String>(),
                sub = userID
            };
        }
        public AuthenticationResponse_with_id_token SVX_MakeAuthorizationResponse_with_id_token(AuthorizationRequest req, IdPAuthenticationEntry idpConc)
        {
            // In the real CodeEndpoint, we would request an
            // IdPAuthenticationEntry for req.SVX_sender, but SVX doesn't know
            // that, so we have to do a concrete check.
            SVX.VProgram_API.Assert(req.SVX_sender == idpConc.authenticatedClient);

            var JwtTokenBody = SVX_Ops.Call(SVX_MakeJwtTokenBody, req, idpConc); 

            SVX.PayloadSecret<JwtTokenBody> id_token1 = getTokenGenerator().Generate(JwtTokenBody, SVX_Principal);
            AuthenticationResponse_with_id_token AuthenticationResponse_with_id_token = new AuthenticationResponse_with_id_token
            {
                access_token = SVX.VProgram_API.Nondet<String>(),
                id_token = id_token1,
                state = req.state
            };

            return AuthenticationResponse_with_id_token;
        }

        public void FakeTokenEndpoint(AccessTokenRequest req, TokenResponse resp)
        {
            // XXX: Anything we can do about this boilerplate?
            var producer = SVX.PrincipalFacet.GenerateNew(SVX_Principal);
            var client = SVX.PrincipalFacet.GenerateNew(SVX_Principal);

            messageStructures.accessTokenRequest.FakeImport(req, producer, client);
            SVX.SVX_Ops.FakeCall(SVX_MakeTokenResponse, req, (AuthorizationCodeParams)null, resp);
            messageStructures.tokenResponse.FakeExportDirectResponse(resp, producer);
        }

        public virtual TokenResponse SVX_MakeTokenResponse(AccessTokenRequest req, AuthorizationCodeParams codeParamsHint)
        {
            // We should only get here with req.grant_type ==
            // "authorization_code", so we don't have to worry about modeling
            // what IdP does in any other case.  Let us know if this isn't true.
            System.Diagnostics.Contracts.Contract.Assert(req.grant_type == "authorization_code");

            authorizationCodeGenerator.Verify(codeParamsHint, req.code);

            if (req.redirect_uri != codeParamsHint.redirect_uri)
                throw new Exception("Authorization code RP mismatch");

            var JwtTokenBody = MakeJwtTokenBody(req.client_id, codeParamsHint.userID);

            SVX.PayloadSecret<JwtTokenBody> id_token1 = getTokenGenerator().Generate(JwtTokenBody, SVX_Principal);
            TokenResponse TokenResponse = new TokenResponse
            {
                id_token = id_token1,
            };

            return TokenResponse;
        }

    }
}
