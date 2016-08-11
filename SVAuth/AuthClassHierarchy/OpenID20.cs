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
using SVX;
using Microsoft.AspNetCore.WebUtilities;

namespace SVAuth.OpenID20
{
    static class OpenID20Standards
    {
        public static SVX.Principal OpenID20ClientIDPrincipal(SVX.Principal idpPrincipal, string realm) =>
          SVX.Principal.Of(idpPrincipal.name + ":" + realm);
    }
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

    /***********************************************************/
    /*               Messages between parties                  */
    /***********************************************************/

    public class AuthenticationRequest : SVX.SVX_MSG
    {
        [JsonProperty("openid.ns")]
        public string openid__ns = "http://specs.openid.net/auth/2.0";
        [JsonProperty("openid.mode")]
        public string openid__mode;
        [JsonProperty("openid.claimed_id")]
        public string openid__claimed_id;
        [JsonProperty("openid.identity")]
        public string openid__identity;
        [JsonProperty("openid.assoc_handle")]
        public string openid__assoc_handle;
        [JsonProperty("openid.return_to")]
        public string openid__return_to;
        [JsonProperty("openid.realm")]
        public string openid__realm;

        // OpenID 2.0 doesn't have a dedicated field for a CSRF protection. This
        // field is added to return_to during marshaling, since SVX normally
        // doesn't allow string concatenation on secrets.
        public SVX.Secret CSRF_state;
    }

    public class FieldsExpectedToBeSigned : SVX.SVX_MSG
    {
        [JsonProperty("openid.claimed_id")]
        public string openid__claimed_id;
        [JsonProperty("openid.identity")]
        public string openid__identity;
        [JsonProperty("openid.return_to")]
        public string openid__return_to;
        [JsonProperty("openid.assoc_handle")]
        public string openid__assoc_handle;
        [JsonProperty("openid.invalidate_handle")]
        public string openid__invalidate_handle;
        [JsonProperty("openid.signed")]
        public string openid__signed;

        // Split off from return_to in secret verifier.
        public SVX.Secret CSRF_state;
    }

    public class AuthenticationResponse : SVX.SVX_MSG
    {
        [JsonProperty("openid.ns")]
        public string openid__ns = "http://specs.openid.net/auth/2.0";
        [JsonProperty("openid.mode")]
        public string openid__mode = "id_res";
        [JsonProperty("openid.op_endpoint")]
        public string openid__op_endpoint;
        [JsonProperty("openid.response_nonce")]
        public string openid__response_nonce;

        public SVX.PayloadSecret<FieldsExpectedToBeSigned> FieldsExpectedToBeSigned;
    }

    [BCTOmit]
    abstract public class MessageStructures
    {
        public readonly SVX.MessageStructure<AuthenticationRequest> authenticationRequest;
        public readonly SVX.MessageStructure<AuthenticationResponse> authenticationResponse;

        protected abstract OpenID20SignedFieldsVerifier getOpenID20SignedFieldsVerifier();
        public MessageStructures(SVX.Principal idpPrincipal)
        {
            authenticationRequest = new SVX.MessageStructure<AuthenticationRequest> { BrowserOnly = true };
            authenticationRequest.AddSecret(nameof(AuthenticationRequest.CSRF_state),
               (msg) => new SVX.PrincipalHandle[] { });

            authenticationResponse = new SVX.MessageStructure<AuthenticationResponse> { BrowserOnly = true };
            authenticationResponse.AddMessagePayloadSecret(nameof(AuthenticationResponse.FieldsExpectedToBeSigned),
                (msg) => new SVX.PrincipalHandle[] { },
                getOpenID20SignedFieldsVerifier(),
                true);
        }
    }

    public abstract class OpenID20SignedFieldsVerifier : MessagePayloadSecretGenerator<FieldsExpectedToBeSigned>
    {

        public Principal IdPPrincipal;

        protected override PrincipalHandle Signer => IdPPrincipal;

        // XXX Eventually this needs to be a parameter.
        protected override PrincipalHandle[] GetReaders(object theParams)
        {
            var FieldsExpectedToBeSigned = (FieldsExpectedToBeSigned)theParams;
            return new PrincipalHandle[] {
                    // Comment this to get an internal error during secret generation.
                    Signer,
                    // Comment either of these to see the secret export check fail.
                    GenericAuth.GenericAuthStandards.GetUrlTargetPrincipal(FieldsExpectedToBeSigned.openid__return_to),
                    GenericAuth.GenericAuthStandards.GetIdPUserPrincipal(IdPPrincipal, FieldsExpectedToBeSigned.openid__identity),
                    // Uncomment to see the verification fail.
                    //Principal.Of("other")
                };
        }
        public abstract FieldsExpectedToBeSigned UnReflectFieldsExpectedToBeSigned(JObject obj);
        protected override OpenID20.FieldsExpectedToBeSigned RawExtractUnverified(string secretValue)
        {
            JObject jObj = Utils.JObjectFromQueryString(secretValue);
            JObject jObj2 = new JObject();
            string signedFields = jObj.Value<string>("openid.signed");
            string[] list = signedFields.Split(',');
            foreach (string element in list)
            {
                string longElement = "openid." + element;
                jObj2[longElement] = jObj[longElement];
            }

            /* The vProgram needs to be able to reason that the reader
             * corresponding to the return_to URL is trusted, but here the
             * return_to URL contains the CSRF_state.  Remove the query here so
             * that (in the non-attack case) the return_to URL matches the
             * originally configured one, which the RelyingParty constructor
             * assumes to act for the RP.  (The URL with the path should be
             * enough to ensure the secret doesn't get leaked; the hostname
             * wouldn't be if the RP has an open redirector.)  This is a little
             * contrived, but the alternatives are worse: if we remove the query
             * in GetReaders, BCT won't be able to analyze it, and if we assume
             * the full return_to URL to act for the RP after some checks,
             * that's probably more prone to security bugs.  A side benefit of
             * this approach: we remove the secret data from the non-SVX.Secret
             * field.
             */
            var returnToUriBuilder = new UriBuilder(jObj2.Value<string>("openid.return_to"));
            var rawCsrfState = QueryHelpers.ParseQuery(returnToUriBuilder.Query)["CSRF_state"];
            returnToUriBuilder.Query = null;
            jObj2["openid.return_to"] = new JValue(returnToUriBuilder.Uri.ToString());

            var signedObj = UnReflectFieldsExpectedToBeSigned(jObj2);
            signedObj.CSRF_state = Secret.Import(rawCsrfState);

            return signedObj;
        }
        protected override string RawGenerate(FieldsExpectedToBeSigned theParams)
        {
            throw new NotImplementedException();
        }

    }



    public abstract class RelyingParty : GenericAuth.RP
    {
        public abstract MessageStructures GetMessageStructures();
        public string realm;
        public string IdP_OpenID20_Uri;
        public string return_to_uri;
        internal StateGenerator stateGenerator;
        public RelyingParty(SVX.Principal rpPrincipal, string IdP_OpenID20_Uri1, string return_to_uri1, string stateKey = null)
            : base(rpPrincipal)
        {
            // Give this a valid value in the vProgram.  FIXME: Doing observably
            // different things in the vProgram is unsound if we aren't careful
            // and poor practice in general.  Once SVX supports passing
            // configuration other than just a principal, use that instead.
            if (return_to_uri1 == null)
                return_to_uri1 = $"https://{rpPrincipal.name}/dummy";
            Uri uri = new Uri(return_to_uri1);
            realm = uri.Host;
            return_to_uri = return_to_uri1;
            IdP_OpenID20_Uri = IdP_OpenID20_Uri1;
            stateGenerator = new StateGenerator(rpPrincipal, stateKey);
            SVX.VProgram_API.AssumeActsFor(GenericAuth.GenericAuthStandards.GetUrlTargetPrincipal(return_to_uri), rpPrincipal);
        }
        protected abstract ModelOpenID20AuthenticationServer CreateModelOpenID20AuthenticationServer();

        protected sealed override SVX.ParticipantId idpParticipantId =>
           SVX.ParticipantId.Of(CreateModelOpenID20AuthenticationServer());

        public abstract AuthenticationRequest createAuthenticationRequest(SVX.PrincipalFacet client);
        public abstract string /*Uri*/ marshalAuthenticationRequest(AuthenticationRequest _AuthorizationRequest);

        [BCTOmit]
        public Task Login_StartAsync(HttpContext httpContext)
        {
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);

            var _AuthenticationRequest = SVX.SVX_Ops.Call(createAuthenticationRequest, context.client);
            if (!BypassCertification)
            {
                // NOTE: We are assuming that the target URL used by
                // marshalAuthorizationRequest belongs to the principal
                // idpParticipantId.principal.  We haven't extended SVX enforcement
                // that far yet.
                GetMessageStructures().authenticationRequest.Export(_AuthenticationRequest, context.client, idpParticipantId.principal);
            }
            _AuthenticationRequest.SVX_serializeSymT = false;

            // Move CSRF_state into return_to.
            _AuthenticationRequest.openid__return_to += "?CSRF_state=" + Uri.EscapeDataString(_AuthenticationRequest.CSRF_state.Export());
            _AuthenticationRequest.CSRF_state = null;

            var rawReq = marshalAuthenticationRequest(_AuthenticationRequest);
            context.http.Response.Redirect(rawReq);

            return Task.CompletedTask;
        }
        public abstract AuthenticationResponse parse_AuthenticationResponse(HttpContext context);
        public abstract GenericAuth.AuthenticationConclusion createConclusion(AuthenticationResponse inputMSG);
        public async Task Login_CallbackAsync(HttpContext httpContext)
        {
            var idp = CreateModelOpenID20AuthenticationServer();
            var dummyAuthenticationRequest = new AuthenticationRequest();
            Trace.Write("Login_CallbackAsync");
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);
            AuthenticationResponse inputMSG = parse_AuthenticationResponse(context.http);

            GetMessageStructures().authenticationResponse.ImportWithModel(inputMSG,
                 () => { idp.FakeAuthenticationEndpoint(dummyAuthenticationRequest, inputMSG); },
                SVX.PrincipalFacet.GenerateNew(SVX_Principal),  // unknown producer
                 context.client);
            Trace.Write("Got Valid AuthenticationResponse");

            GenericAuth.AuthenticationConclusion conclusion = SVX_Ops.Call(createConclusion,inputMSG);
            if (conclusion == null)
            {
                context.http.Response.Redirect(context.http.Request.Cookies["LoginPageUrl"]);
                return;
            }

            await AuthenticationDone(conclusion, context);
        }
    }
    public abstract class ModelOpenID20AuthenticationServer : GenericAuth.AS
    {
        protected abstract MessageStructures getMessageStrctures();
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

        protected abstract OpenID20SignedFieldsVerifier getSignedFieldsGenerator();
        public ModelOpenID20AuthenticationServer(SVX.Principal idpPrincipal)
           : base(idpPrincipal)
        {
        }
        public class IdPAuthenticationEntry : SVX.SVX_MSG
        {
            public SVX.PrincipalHandle authenticatedClient;
            public string userID;
        }

        public void FakeAuthenticationEndpoint(AuthenticationRequest req, AuthenticationResponse resp)
        {
            // XXX: Do we need to check that req.response_type == "code"?
            // Currently, as per the comment in
            // AuthorizationCodeFlow_Login_CallbackAsync, FakeCodeEndpoint only
            // needs to handle the kinds of requests actually made by RP, which
            // request a code.  We don't care about the value of
            // req.response_type in its own right.

            var producer = SVX.PrincipalFacet.GenerateNew(SVX_Principal);
            var client = SVX.PrincipalFacet.GenerateNew(SVX_Principal);

            messageStructures.authenticationRequest.FakeImport(req, producer, client);

            var idpConc = new IdPAuthenticationEntry();  // Nondet
            SVX.SVX_Ops.FakeCall(SVX_ConcludeClientAuthentication, idpConc, idpConc);

            SVX.SVX_Ops.FakeCall(SVX_MakeAuthenticationResponse, req, idpConc, resp);

            messageStructures.authenticationResponse.FakeExport(resp);
        }
        // Write lambda by hand because all compiler-generated classes are
        // currently excluded from decompilation of method bodies by CCI.
        class SignedInDeclarer
        {
            internal ModelOpenID20AuthenticationServer outer;
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
        public FieldsExpectedToBeSigned SVX_MakeSignedFields(AuthenticationRequest req, IdPAuthenticationEntry idpConc)
        {
            return MakeSignedFields(req.openid__realm, idpConc.userID, req.openid__return_to, req.CSRF_state);
        }
        public FieldsExpectedToBeSigned MakeSignedFields(string realm, string userID, string return_to, SVX.Secret state)
        {
            return new FieldsExpectedToBeSigned
            {
                openid__claimed_id = userID,
                openid__identity = userID,
                openid__return_to = return_to,
                openid__assoc_handle = SVX.VProgram_API.Nondet<String>(),
                openid__invalidate_handle = SVX.VProgram_API.Nondet<String>(),
                openid__signed = SVX.VProgram_API.Nondet<String>(),
                CSRF_state = state
            };
        }
        public AuthenticationResponse SVX_MakeAuthenticationResponse(AuthenticationRequest req, IdPAuthenticationEntry idpConc)
        {
            // In the real CodeEndpoint, we would request an
            // IdPAuthenticationEntry for req.SVX_sender, but SVX doesn't know
            // that, so we have to do a concrete check.
            SVX.VProgram_API.Assert(req.SVX_sender == idpConc.authenticatedClient);

            var SignedFieldsParams = SVX_Ops.Call(SVX_MakeSignedFields, req, idpConc);
            SVX.PayloadSecret<FieldsExpectedToBeSigned> SignedFields = getSignedFieldsGenerator().Generate(SignedFieldsParams, SVX_Principal);
            return new AuthenticationResponse
            {
                openid__op_endpoint = SVX.VProgram_API.Nondet<String>(),
                openid__response_nonce = SVX.VProgram_API.Nondet<String>(),
                FieldsExpectedToBeSigned = SignedFields
            };
        }
    }
}
