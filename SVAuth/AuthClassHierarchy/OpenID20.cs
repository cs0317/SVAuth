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

namespace SVAuth.OpenID20
{
    static class OpenID20Standards
    {
        public static SVX.Principal OpenID20ClientIDPrincipal(SVX.Principal idpPrincipal, string realm) =>
          SVX.Principal.Of(idpPrincipal.name + ":" + realm);
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

        // This automatically gets set when the IdP generates a redirection to
        // the return_to URL we specified, which contains a CSRF_state
        // parameter.
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
    public class MessageStructures<TAuthenticationResponse, TSignedFields>
        where TAuthenticationResponse: AuthenticationResponse where TSignedFields: FieldsExpectedToBeSigned
    {
        public readonly SVX.MessageStructure<AuthenticationRequest> authenticationRequest;
        public readonly SVX.MessageStructure<TAuthenticationResponse> authenticationResponse;
        
        //protected abstract OpenID20SignedFieldsVerifier getTokenVerifier();
        public MessageStructures(SVX.Principal idpPrincipal)
        {
            authenticationRequest = new SVX.MessageStructure<AuthenticationRequest> { BrowserOnly = true };
            authenticationRequest.AddSecret(nameof(AuthenticationRequest.CSRF_state),
               (msg) => new SVX.PrincipalHandle[] { });

            authenticationResponse = new SVX.MessageStructure<TAuthenticationResponse> { BrowserOnly = true };
            authenticationResponse.AddMessagePayloadSecret(nameof(AuthenticationResponse<TSignedFields>.FieldsExpectedToBeSigned),
                (msg) => new SVX.PrincipalHandle[] { },
                YahooSignedFieldsVerifier,
                true);
            authenticationResponse.AddSecret(nameof(FieldsExpectedToBeSigned.CSRF_state),
                (msg) => new SVX.PrincipalHandle[] { });
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
            jObj2["openid.return_to"] = new JValue(
                new UriBuilder(jObj2.Value<string>("openid.return_to")) { Query = null }.Uri.ToString());

            return UnReflectFieldsExpectedToBeSigned(jObj2);
        }
        protected override string RawGenerate(FieldsExpectedToBeSigned theParams)
        {
            throw new NotImplementedException();
        }

    }

    

    public abstract class RelyingParty : GenericAuth.RP 
    {
        MessageStructures<AuthenticationResponse<TSignedFields>,TSignedFields> messageStructures_;
        MessageStructures<AuthenticationResponse<TSignedFields>,TSignedFields> messageStructures
        {
            get
            {
                if (messageStructures_ == null)
                    messageStructures_ = new MessageStructures<AuthenticationResponse<TSignedFields>, TSignedFields>(idpParticipantId.principal);
                return messageStructures_;
            }
        }
        public string realm;
        public string IdP_OpenID20_Uri;
        public string return_to_uri;
        public RelyingParty(SVX.Principal rpPrincipal, string IdP_OpenID20_Uri1, string return_to_uri1)
            : base(rpPrincipal)
        {
            Uri uri = new Uri(return_to_uri1);
            realm = uri.Host;
            return_to_uri = return_to_uri1;
            IdP_OpenID20_Uri = IdP_OpenID20_Uri1;
        }
        protected abstract ModelOpenID20AuthenticationServer CreateModelOpenID20AuthenticationServer();

        protected sealed override SVX.ParticipantId idpParticipantId =>
           SVX.ParticipantId.Of(CreateModelOpenID20AuthenticationServer());

        public abstract AuthenticationRequest createAuthenticationRequest(SVX.PrincipalFacet client);
        public abstract string /*Uri*/ marshalAuthenticationRequest(AuthenticationRequest _AuthorizationRequest);
        public Task Login_StartAsync(HttpContext httpContext)
        {
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);

            var _AuthenticationRequest = SVX.SVX_Ops.Call(createAuthenticationRequest,context.client);
            if (!BypassCertification)
            {
                // NOTE: We are assuming that the target URL used by
                // marshalAuthorizationRequest belongs to the principal
                // idpParticipantId.principal.  We haven't extended SVX enforcement
                // that far yet.
                messageStructures.authenticationRequest.Export(_AuthenticationRequest, context.client, idpParticipantId.principal);
            }
            _AuthenticationRequest.SVX_serializeSymT = false;

            // Move CSRF_state into return_to.
            _AuthenticationRequest.openid__return_to += "?CSRF_state=" + Uri.EscapeDataString(_AuthenticationRequest.CSRF_state.Export());
            _AuthenticationRequest.CSRF_state = null;

            var rawReq = marshalAuthenticationRequest(_AuthenticationRequest);
            context.http.Response.Redirect(rawReq);

            return Task.CompletedTask;
        }
        //public abstract AuthenticationResponse verify_and_parse_AuthenticationResponse(HttpContext context);
        public abstract GenericAuth.AuthenticationConclusion createConclusion(AuthenticationResponse inputMSG);
        public async Task Login_CallbackAsync(HttpContext httpContext)
        {
            Trace.Write("Login_CallbackAsync");
            var context = new SVAuthRequestContext(SVX_Principal, httpContext);
            AuthenticationResponse inputMSG = verify_and_parse_AuthenticationResponse(context.http);
            // Just enough for createConclusion until we do a real SVX import.
            inputMSG.SVX_sender = context.client;

            if (inputMSG==null)
            {
                context.http.Response.Redirect(context.http.Request.Cookies["LoginPageUrl"]);
                return;
            }
            Trace.Write("Got Valid AuthenticationResponse");

            GenericAuth.AuthenticationConclusion conclusion = createConclusion(inputMSG);
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
        public ModelOpenID20AuthenticationServer(SVX.Principal idpPrincipal)
           : base(idpPrincipal)
        {
            // Initialization order restriction
            authorizationCodeGenerator = new AuthorizationCodeGenerator(SVX_Principal);
        }
    }
