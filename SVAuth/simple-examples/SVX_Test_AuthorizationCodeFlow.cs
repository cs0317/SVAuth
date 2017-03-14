using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading.Tasks;
using SVX;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace SVAuth
{
    // Obviously, much of this is copy and paste from SVX_Test_ImplicitFlow,
    // but factoring out the commonality would have been a distraction from this
    // exercise.  We'll see that factoring out when we migrate the real
    // implementations to SVX2.
    public static class SVX_Test_AuthorizationCodeFlow
    {
        static readonly Entity googlePrincipal = Entity.Of("Google");
        static readonly Entity mattMerchantPrincipal = Entity.Of("MattMerchant");

        static Entity GoogleUserPrincipal(string googleUsername)
        {
            return Entity.Of("Google:" + googleUsername);
        }

        // Accessibility constraint on RawGenerate that doesn't seem to make sense in this case.
        public class AuthorizationCodeParams
        {
            // Corresponds to GoogleUserPrincipal(username)
            public string googleUsername;
            public Entity rpPrincipal;
        }

        public class GoogleAuthorizationCodeGenerator : SecretGenerator<AuthorizationCodeParams>
        {
            // We could make the idpPrincipal a parameter, but don't bother yet.

            protected override Principal[] GetReaders(object theParams)
            {
                var params2 = (AuthorizationCodeParams)theParams;
                return new Entity[] {
                    // Comment this to get an internal error during secret generation.
                    googlePrincipal,
                    // Comment either of these to see the secret export check fail.
                    params2.rpPrincipal,
                    GoogleUserPrincipal(params2.googleUsername),
                    // Uncomment to see the verification fail.
                    //Principal.Of("other")
                };
            }

            protected override string RawGenerate(AuthorizationCodeParams theParams)
            {
                // Nothing actually secret. :)
                return JsonConvert.SerializeObject(theParams);
            }

            protected override void RawVerify(AuthorizationCodeParams theParams, string secretValue)
            {
                if (secretValue != RawGenerate(theParams))
                    throw new ArgumentException();
            }
        }

        static MessageStructure<AuthorizationCodeRequest> authorizationCodeRequestStructure;
        static MessageStructure<AuthorizationCodeResponse> authorizationCodeResponseStructure;

        static MessageStructure<ValidationRequest> validationRequestStructure;
        static MessageStructure<ValidationResponse> validationResponseStructure;

        public class AuthorizationCodeRequest : SVX_MSG
        {
            public Entity rpPrincipal;
            public Secret state;
        }
        public class AuthorizationCodeResponse : SVX_MSG
        {
            public Secret authorizationCode;
            public Secret state;
        }
        public class ValidationRequest : SVX_MSG
        {
            public Entity rpPrincipal;
            public Secret authorizationCode;
        }
        public class ValidationResponse : SVX_MSG
        {
            public string googleUsername;
        }

        public class IdPAuthenticationEntry : SVX_MSG
        {
            public Principal authenticatedClient;
            public string googleUsername;
        }
        public class RPAuthenticationConclusion : SVX_MSG
        {
            public Principal authenticatedClient;
            public string googleUsername;
        }

        public class Google_IdP : Participant
        {
            public Google_IdP(Entity principal) : base(principal)
            {
                // Not bothering to make the idpPrincipal a parameter.
                Contract.Assert(principal == googlePrincipal);
            }

            private GoogleAuthorizationCodeGenerator authorizationCodeGenerator = new GoogleAuthorizationCodeGenerator();

            private DeclarablePredicate<Entity /*underlying client*/, string /*username*/> SignedInPredicate
                = new DeclarablePredicate<Entity, string>();

            private Dictionary<Secret, AuthorizationCodeParams> authorizationCodeParamsDict = new Dictionary<Secret, AuthorizationCodeParams>();

            public string CodeEndpoint(Principal client, string codeRequestStr)
            {
                var req = JsonConvert.DeserializeObject<AuthorizationCodeRequest>(codeRequestStr);
                authorizationCodeRequestStructure.Import(req,
                    // We don't know who produced the request.
                    Channel.GenerateNew(SVX_Principal),
                    client);

                // In reality, AuthenticateClient couldn't be done
                // synchronously, so both CodeEndpoint and AuthenticateClient
                // would be broken into a start and a callback.
                var idpConc = AuthenticateClient(client);

                var resp = SVX_Ops.Call(SVX_MakeAuthorizationCodeResponse, req, idpConc);

                authorizationCodeParamsDict[resp.authorizationCode] = new AuthorizationCodeParams
                {
                    rpPrincipal = req.rpPrincipal,
                    googleUsername = idpConc.googleUsername
                };

                authorizationCodeResponseStructure.Export(resp, client, req.rpPrincipal);
                return JsonConvert.SerializeObject(resp);
            }

            IdPAuthenticationEntry AuthenticateClient(Principal client)
            {
                // In reality, once the user logs in, we would store the
                // IdPAuthenticationEntry in the session data structure of the
                // web application framework.
                var username = "Alice";
                return SVX_Ops.Call(SVX_ConcludeClientAuthentication, new IdPAuthenticationEntry {
                    authenticatedClient = client,
                    googleUsername = username,
                });
            }

            // Write lambda by hand because all compiler-generated classes are
            // currently excluded from decompilation of method bodies by CCI.
            class SignedInDeclarer
            {
                internal Google_IdP outer;
                internal IdPAuthenticationEntry entry;
                internal void Declare()
                {
                    outer.SignedInPredicate.Declare(VProgram_API.UnderlyingPrincipal(entry.authenticatedClient), entry.googleUsername);
                }
            }

            public IdPAuthenticationEntry SVX_ConcludeClientAuthentication(IdPAuthenticationEntry entry)
            {
                var d = new SignedInDeclarer { outer = this, entry = entry };
                SVX_Ops.Ghost(d.Declare);
                VProgram_API.AssumeActsFor(entry.authenticatedClient, GoogleUserPrincipal(entry.googleUsername));
                // Reuse the message... Should be able to get away with it.
                return entry;
            }

            public AuthorizationCodeResponse SVX_MakeAuthorizationCodeResponse(AuthorizationCodeRequest req, IdPAuthenticationEntry idpConc)
            {
                // In CodeEndpoint, we requested an IdPAuthenticationEntry for
                // req.SVX_sender, but SVX doesn't know that, so we have to do a
                // concrete check.
                VProgram_API.Assert(req.SVX_sender == idpConc.authenticatedClient);

                // With this expression inlined below, BCT silently mistranslated the code.
                var theParams = new AuthorizationCodeParams
                {
                    rpPrincipal = req.rpPrincipal,
                    googleUsername = idpConc.googleUsername
                };
                var authorizationCode = authorizationCodeGenerator.Generate(theParams, googlePrincipal);

                return new AuthorizationCodeResponse
                {
                    authorizationCode = authorizationCode,
                    state = req.state
                };
            }

            public string ValidationEndpoint(string validationRequestStr)
            {
                Principal producer = Channel.GenerateNew(googlePrincipal);
                Principal client = Channel.GenerateNew(googlePrincipal);

                var req = JsonConvert.DeserializeObject<ValidationRequest>(validationRequestStr);
                validationRequestStructure.Import(req,
                    producer,
                    client);

                var resp = SVX_Ops.Call(SVX_MakeValidationResponse, req,
                    authorizationCodeParamsDict[req.authorizationCode]);

                validationResponseStructure.ExportDirectResponse(resp, client, producer);
                return JsonConvert.SerializeObject(resp);
            }

            public ValidationResponse SVX_MakeValidationResponse(ValidationRequest req, AuthorizationCodeParams paramsHint)
            {
                // As long as we're using the interim implementation of
                // AssumeValidSecret that assumes the parameters of equal
                // secrets are reference equal, it's critical that we don't do
                // anything that will introduce a contradiction.  With paramsHint
                // as nondet, we should be OK for now.

                // Comment out these 2 lines to see the verification fail.
                if (paramsHint.rpPrincipal != req.rpPrincipal)
                    throw new Exception("Authorization code RP mismatch");
                authorizationCodeGenerator.Verify(paramsHint, req.authorizationCode);
                return new ValidationResponse
                {
                    googleUsername = paramsHint.googleUsername
                };
            }

            public bool Ghost_CheckSignedIn(Entity underlyingPrincipal, string username)
            {
                return SignedInPredicate.Check(underlyingPrincipal, username);
            }
        }

        class StateParams
        {
            // We expect this to be a facet issued by the RP.
            public Principal client;
            public Entity idpPrincipal;
        }
        class StateGenerator : SecretGenerator<StateParams>
        {
            readonly Entity rpPrincipal;
            internal StateGenerator(Entity rpPrincipal)
            {
                this.rpPrincipal = rpPrincipal;
            }

            protected override Principal[] GetReaders(object theParams)
            {
                var params2 = (StateParams)theParams;
                return new Principal[] { params2.idpPrincipal, rpPrincipal, params2.client };
            }

            protected override string RawGenerate(StateParams theParams)
            {
                // Pretend this does an HMAC with an RP-specific key.
                return JsonConvert.SerializeObject(theParams);
            }

            protected override void RawVerify(StateParams theParams, string secretValue)
            {
                if (secretValue != RawGenerate(theParams))
                    throw new ArgumentException();
            }
        }

        public class MattMerchant_RP : Participant
        {
            public MattMerchant_RP(Entity principal) : base(principal)
            {
                stateGenerator = new StateGenerator(principal);
            }

            StateGenerator stateGenerator;

            // Something here is tripping up BCT.  Just exclude it until we have
            // fully as-needed translation.
            [BCTOmitImplementation]
            public string LoginStart(Principal client)
            {
                var req = new AuthorizationCodeRequest
                {
                    rpPrincipal = SVX_Principal,
                    state = stateGenerator.Generate(
                        new StateParams { client = client, idpPrincipal = googlePrincipal },
                        SVX_Principal)
                };
                authorizationCodeRequestStructure.Export(req, client, googlePrincipal);
                return JsonConvert.SerializeObject(req);
            }

            public void LoginCallback(Principal client, string idTokenResponseStr, Google_IdP idp)
            {
                var authorizationCodeResponse = JsonConvert.DeserializeObject<AuthorizationCodeResponse>(idTokenResponseStr);
                authorizationCodeResponseStructure.Import(authorizationCodeResponse,
                    // We don't know who produced the redirection.
                    Channel.GenerateNew(SVX_Principal),
                    client);

                var validationRequest = SVX_Ops.Call(SVX_MakeValidationRequest, authorizationCodeResponse);

                validationRequestStructure.Export(validationRequest, googlePrincipal, null);
                var validationRequestStr = JsonConvert.SerializeObject(validationRequest);

                var validationResponseStr = idp.ValidationEndpoint(validationRequestStr);

                var validationResponse = JsonConvert.DeserializeObject<ValidationResponse>(validationResponseStr);
                validationResponseStructure.ImportDirectResponse(validationResponse, googlePrincipal, SVX_Principal);

                // SVX will automatically detect using message IDs that
                // validationResponse actually resulted from
                // authorizationCodeResponse and not merely another message with
                // the same SymT.  This is essential for us to establish the
                // relationship between authorizationCodeResponse.SVX_sender and
                // validationResponse.googleUsername.
                var conc = SVX_Ops.Call(SVX_SignInRP, authorizationCodeResponse, validationResponse);

                SVX_Ops.Certify(conc, LoginSafety);
                SVX_Ops.Certify(conc, LoginXSRFPrevention, new ParticipantId(googlePrincipal, typeof(Google_IdP)));
                // AbandonAndCreateSession...
            }

            public ValidationRequest SVX_MakeValidationRequest(AuthorizationCodeResponse resp)
            {
                // May as well fail fast.  It should also pass verification to do this in SVX_SignInRP.
                // Pull new { ... } out to work around BCT mistranslation.
                var stateParams = new StateParams { client = resp.SVX_sender, idpPrincipal = googlePrincipal };
                stateGenerator.Verify(stateParams, resp.state);
                return new ValidationRequest
                {
                    authorizationCode = resp.authorizationCode,
                    rpPrincipal = SVX_Principal  // Like in the original authorization code request.
                };
            }

            public RPAuthenticationConclusion SVX_SignInRP(
                AuthorizationCodeResponse authorizationCodeResponse, ValidationResponse validationResponse)
            {
                return new RPAuthenticationConclusion {
                    authenticatedClient = authorizationCodeResponse.SVX_sender,
                    googleUsername = validationResponse.googleUsername
                };
            }

            public bool LoginSafety(RPAuthenticationConclusion conc)
            {
                var googleUser = GoogleUserPrincipal(conc.googleUsername);
                VProgram_API.AssumeTrustedServer(googlePrincipal);
                VProgram_API.AssumeTrustedServer(SVX_Principal);
                VProgram_API.AssumeTrusted(googleUser);

                return VProgram_API.ActsFor(conc.authenticatedClient, googleUser);
            }

            public bool LoginXSRFPrevention(RPAuthenticationConclusion conc)
            {
                VProgram_API.AssumeTrustedServer(googlePrincipal);
                VProgram_API.AssumeTrustedServer(SVX_Principal);
                VProgram_API.AssumeTrustedBrowser(conc.authenticatedClient);

                var idp = VProgram_API.GetParticipant<Google_IdP>(googlePrincipal);
                return idp.Ghost_CheckSignedIn(VProgram_API.UnderlyingPrincipal(conc.authenticatedClient), conc.googleUsername);
            }
        }

        [BCTOmitImplementation]
        static void InitializeMessageStructures()
        {
            // In all cases, we only bother declaring the secret readers we
            // actually need for the protocol flow.  Maybe this is a bad habit.

            authorizationCodeRequestStructure = new MessageStructure<AuthorizationCodeRequest>() { BrowserOnly = true };
            authorizationCodeRequestStructure.AddSecret(nameof(AuthorizationCodeRequest.state),
                // The sender (the client) gets implicitly added.
                (msg) => new Principal[] { msg.rpPrincipal });

            authorizationCodeResponseStructure = new MessageStructure<AuthorizationCodeResponse>() { BrowserOnly = true };
            authorizationCodeResponseStructure.AddSecret(nameof(AuthorizationCodeRequest.state),
                (msg) => new Principal[] { });
            authorizationCodeResponseStructure.AddSecret(nameof(AuthorizationCodeResponse.authorizationCode),
                (msg) => new Principal[] { googlePrincipal });

            validationRequestStructure = new MessageStructure<ValidationRequest>();
            validationRequestStructure.AddSecret(nameof(AuthorizationCodeResponse.authorizationCode),
                (msg) => new Principal[] { });

            // Nothing interesting here.
            validationResponseStructure = new MessageStructure<ValidationResponse>();
        }

        // Do not BCTOmitImplementation this; it affects some static field initializers that we want.
        static SVX_Test_AuthorizationCodeFlow()
        {
            InitializeMessageStructures();
        }

        [BCTOmitImplementation]
        public static void Test()
        {
            var idp = new Google_IdP(googlePrincipal);
            var rp = new MattMerchant_RP(Entity.Of("MattMerchant"));

            var aliceIdP = Channel.GenerateNew(googlePrincipal);
            var aliceRP = Channel.GenerateNew(rp.SVX_Principal);

            var codeRequestStr = rp.LoginStart(aliceRP);
            var codeResponseStr = idp.CodeEndpoint(aliceIdP, codeRequestStr);
            rp.LoginCallback(aliceRP, codeResponseStr, idp);  // Includes the validation server-to-server call
        }
    }
}
