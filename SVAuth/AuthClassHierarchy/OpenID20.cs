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

        //OpenID 2.0 doesn't have a field for a CSRF protection. It is up to the derived class to decide what value to fill in. 
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

        //OpenID 2.0 doesn't have a field for a CSRF protection. It is up to the derived class to decide what value to fill in. 
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
                    OpenID20Standards.OpenID20ClientIDPrincipal(IdPPrincipal, new Uri(FieldsExpectedToBeSigned.openid__return_to).Host),
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
            var list = signedFields.Split(',');
            foreach (var element in list)
            {
                jObj2[element] = jObj[element];
            }

            jObj2["CSRF_state"]=Utils.
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
