using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
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
        public string nonce = "123";
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
        public string aud, iss, exp, sub, nonce;
    }

    public abstract class OIDCTokenVerifier : MessagePayloadSecretGenerator<JwtTokenBody>
    {

        public Entity IdPPrincipal;

        protected override Principal Signer => IdPPrincipal;

        // XXX Eventually this needs to be a parameter.
        protected override Principal[] GetReaders(object theParams)
        {
            var body = (JwtTokenBody)theParams;
            return new Principal[] {
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
        public MessageStructures(SVX.Entity idpPrincipal) : base(idpPrincipal)
        {
            authenticationResponse_with_id_token = new SVX.MessageStructure<AuthenticationResponse_with_id_token> { BrowserOnly = true };
            authenticationResponse_with_id_token.AddMessagePayloadSecret(nameof(AuthenticationResponse_with_id_token.id_token),
                (msg) => new SVX.Principal[] { },
                getTokenVerifier(),
                true);
            authenticationResponse_with_id_token.AddSecret(nameof(AuthenticationResponse_with_id_token.state),
               (msg) => new SVX.Principal[] { });

            tokenResponse = new SVX.MessageStructure<TokenResponse>();
            tokenResponse.AddMessagePayloadSecret(nameof(TokenResponse.id_token),
                (msg) => new SVX.Principal[] { },
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
        public RelyingParty(SVX.Entity rpPrincipal, string client_id1, string redierct_uri1, string client_secret1, 
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

        JObject detach_concdst_conckey_formpost(ref SVAuthRequestContext context, string delim)
        {
            JObject jo = new JObject(context.http.Request.Form.Select(q => new JProperty(q.Key, q.Value.Single())));
            string state = jo["state"].ToString();
            if (String.IsNullOrEmpty(state))
                throw new Exception("The STATE parameter is missing.");

            int pos1 = state.IndexOf(delim);
            if (pos1 > 1)
            {
                int pos2 = state.Substring(pos1 + 2).IndexOf(delim);
                if (pos2 > 1)
                {
                    context.concdst = System.Net.WebUtility.UrlDecode(state.Substring(0, pos1));
                    context.conckey = System.Net.WebUtility.UrlDecode(state.Substring(pos1 + 2, pos2));
                    var state1 = state.Substring(pos1 + pos2 + 2 + 2);
                    jo["state"] = state1;
                }
            }
            return jo;
        }

        public override async Task AuthorizationCodeFlow_Login_CallbackAsync(HttpContext httpContext)
        {
            var idp = CreateModelOIDCAuthenticationServer();
            Trace.Write("AuthorizationCodeFlow_Login_CallbackAsync");
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);

            var dummyAuthorizationRequest = new AuthorizationRequest();

            //Matt's original implementation, without detaching concdst_conckey
            /*var authorizationResponse = (OAuth20.AuthorizationResponse)Utils.ObjectFromFormPost(
                context.http.Request.Form,typeof(OAuth20.AuthorizationResponse));
                */

            JObject jo = detach_concdst_conckey_formpost(ref context, "  ");
            AuthorizationResponse authorizationResponse = (AuthorizationResponse)Utils.UnreflectObject(jo, typeof(AuthorizationResponse)); ;

            GetMessageStructures().authorizationResponse.ImportWithModel(authorizationResponse,
               () => { idp.FakeCodeEndpoint(dummyAuthorizationRequest, authorizationResponse); },
                SVX.Channel.GenerateNew(SVX_Principal),  // unknown producer
                context.channel);
            /*GetMessageStructures().authorizationResponse.Import(authenticationResponse,
                SVX.PrincipalFacet.GenerateNew(SVX_Principal),  // unknown producer
                context.client);*/

            var _AccessTokenRequest = SVX.SVX_Ops.Call(createAccessTokenRequest, authorizationResponse);

            GetMessageStructures().accessTokenRequest.Export(_AccessTokenRequest, idpParticipantId.principal, null);
            var rawReq = marshalAccessTokenRequest(_AccessTokenRequest);
            var RawAccessTokenResponse = await Utils.PerformHttpRequestAsync(rawReq);
           
            Trace.Write("Got AccessTokenResponse");

            JObject jObject = JObject.Parse(RawAccessTokenResponse.Content.ReadAsStringAsync().Result);
            TokenResponse tokenResponse = Utils.UnreflectObject<TokenResponse>(jObject);
            GetMessageStructures().tokenResponse.ImportDirectResponseWithModel(tokenResponse,
                    () => { idp.FakeTokenEndpoint(_AccessTokenRequest, tokenResponse); },
                    idpParticipantId.principal,
                    SVX_Principal
                );
            
            if (!String.IsNullOrEmpty(tokenResponse.id_token.theParams.nonce))
            {
                HashAlgorithm hashAlgo = SHA1.Create();
                string expected_nonce = BitConverter.ToString(hashAlgo.ComputeHash(System.Text.Encoding.UTF8.GetBytes(context.channel.id)));
                if (expected_nonce!= tokenResponse.id_token.theParams.nonce)
                    throw new Exception("invalid nonce");
            }
            var conclusion = SVX.SVX_Ops.Call(createConclusionOidc, authorizationResponse, tokenResponse);
            await AuthenticationDone(conclusion, context);
        }
        public virtual GenericAuth.AuthenticationConclusion createConclusionOidcImplicit(
            AuthenticationResponse_with_id_token authenticationResponse) { return null; }

        

        public async Task ImplicitFlow_Login_CallbackAsync(HttpContext httpContext)
        {
            Trace.Write("ImplicitFlow_Login_CallbackAsync");
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);
           
            //Matt's original implementation, without detaching concdst_conckey
            /*AuthenticationResponse_with_id_token authenticationResponse_with_id_token= (AuthenticationResponse_with_id_token)Utils.ObjectFromFormPost
                (context.http.Request.Form, typeof(AuthenticationResponse_with_id_token));
                */
            JObject jo = detach_concdst_conckey_formpost(ref context, "  ");
            AuthenticationResponse_with_id_token authenticationResponse_with_id_token = (AuthenticationResponse_with_id_token)Utils.UnreflectObject(jo, typeof(AuthenticationResponse_with_id_token)); ;
            var idp = CreateModelOIDCAuthenticationServer();
            var dummyAuthorizationRequest = new AuthorizationRequest();

            GetMessageStructures().authenticationResponse_with_id_token.ImportWithModel(authenticationResponse_with_id_token,
                () => { idp.FakeImplicitFlowIDTokenEndpoint(dummyAuthorizationRequest, authenticationResponse_with_id_token); },
                SVX.Channel.GenerateNew(SVX_Principal),  // unknown producer
                context.channel);
            Trace.Write("Got Valid AuthenticationResponse");

            if (!String.IsNullOrEmpty(authenticationResponse_with_id_token.id_token.theParams.nonce))
            {
                HashAlgorithm hashAlgo = SHA1.Create();
                string expected_nonce = BitConverter.ToString(hashAlgo.ComputeHash(System.Text.Encoding.UTF8.GetBytes(context.channel.id)));
                if (expected_nonce != authenticationResponse_with_id_token.id_token.theParams.nonce)
                    throw new Exception("invalid nonce");
            }

            GenericAuth.AuthenticationConclusion conclusion = SVX_Ops.Call(createConclusionOidcImplicit,authenticationResponse_with_id_token);
            if (conclusion == null)
            {
                context.http.Response.StatusCode = 303;
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

        public ModelOIDCAuthenticationServer(SVX.Entity idpPrincipal)
            : base(idpPrincipal)
        {
            // Initialization order restriction
            authorizationCodeGenerator = new AuthorizationCodeGenerator(SVX_Principal);
        }

        public class IdPAuthenticationEntry : SVX.SVX_MSG
        {
            public SVX.Principal channel;
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

            var producer = SVX.Channel.GenerateNew(SVX_Principal);
            var client = SVX.Channel.GenerateNew(SVX_Principal);

            messageStructures.authorizationRequest.FakeImport(req, producer, client);

            var idpConc = new IdPAuthenticationEntry();  // Nondet
            SVX.SVX_Ops.FakeCall(SVX_ConcludeClientAuthentication, idpConc, idpConc);

            SVX.SVX_Ops.FakeCall(SVX_MakeAuthorizationResponse, req, idpConc, resp);

            messageStructures.authorizationResponse.FakeExport(resp);
        }

        public void FakeImplicitFlowIDTokenEndpoint(AuthorizationRequest req, AuthenticationResponse_with_id_token resp)
        {
            var producer = SVX.Channel.GenerateNew(SVX_Principal);
            var client = SVX.Channel.GenerateNew(SVX_Principal);

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
                outer.BrowserOwnedBy.Declare(SVX.VProgram_API.Owner(entry.channel), entry.userID);
            }
        }

        public IdPAuthenticationEntry SVX_ConcludeClientAuthentication(IdPAuthenticationEntry entry)
        {
            var d = new SignedInDeclarer { outer = this, entry = entry };
            SVX.SVX_Ops.Ghost(d.Declare);
            SVX.VProgram_API.AssumeActsFor(entry.channel,
                GenericAuth.GenericAuthStandards.GetIdPUserPrincipal(SVX_Principal, entry.userID));
            // Reuse the message... Should be able to get away with it.
            return entry;
        }

        public AuthorizationResponse SVX_MakeAuthorizationResponse(AuthorizationRequest req, IdPAuthenticationEntry idpConc)
        {
            // In the real CodeEndpoint, we would request an
            // IdPAuthenticationEntry for req.SVX_sender, but SVX doesn't know
            // that, so we have to do a concrete check.
            SVX.VProgram_API.Assert(req.SVX_sender == idpConc.channel);

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
            // In the real ImplicitFlowIDTokenEndpoint, we would request an
            // IdPAuthenticationEntry for req.SVX_sender, but SVX doesn't know
            // that, so we have to do a concrete check.
            SVX.VProgram_API.Assert(req.SVX_sender == idpConc.channel);

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
            var producer = SVX.Channel.GenerateNew(SVX_Principal);
            var client = SVX.Channel.GenerateNew(SVX_Principal);

            messageStructures.accessTokenRequest.FakeImport(req, producer, client);
            SVX.SVX_Ops.FakeCall(SVX_MakeTokenResponse, req, (AuthorizationCodeParams)null, resp);
            messageStructures.tokenResponse.FakeExportDirectResponse(resp, producer);
        }

        public virtual TokenResponse SVX_MakeTokenResponse(AccessTokenRequest req, AuthorizationCodeParams codeParamsHint)
        {
            // We should only get here with req.grant_type ==
            // "authorization_code", so we don't have to worry about modeling
            // what IdP does in any other case.
            if (req.grant_type != "authorization_code")
                return VProgram_API.Nondet<TokenResponse>();

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
