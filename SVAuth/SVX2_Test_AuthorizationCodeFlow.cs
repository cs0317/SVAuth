using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading.Tasks;
using SVX2;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace SVAuth
{
    public static class SVX2_Test_AuthorizationCodeFlow
    {
        static readonly Principal googlePrincipal = Principal.Of("Google");
        static readonly Principal mattMerchantPrincipal = Principal.Of("MattMerchant");

        static Principal GoogleUserPrincipal(string googleUsername)
        {
            return Principal.Of("Google:" + googleUsername);
        }

        // Accessibility constraint on RawGenerate that doesn't seem to make sense in this case.
        public class AuthorizationCodeParams
        {
            // Corresponds to GoogleUserPrincipal(username)
            public string googleUsername;
            public Principal rpPrincipal;
        }

        public class GoogleAuthorizationCodeGenerator : SecretGenerator<AuthorizationCodeParams>
        {
            protected override PrincipalHandle[] GetReaders(object theParams)
            {
                var params2 = (AuthorizationCodeParams)theParams;
                return new Principal[] {
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
            public Principal rpPrincipal;
            public Secret state;
        }
        public class AuthorizationCodeResponse : SVX_MSG
        {
            public Secret authorizationCode;
            public Secret state;
        }
        public class ValidationRequest : SVX_MSG
        {
            public Principal rpPrincipal;
            public Secret authorizationCode;
        }
        public class ValidationResponse : SVX_MSG
        {
            public string googleUsername;
        }

        public class IdPAuthenticationEntry : SVX_MSG
        {
            public PrincipalHandle authenticatedClient;
            public string googleUsername;
        }
        // This is an SVX_MSG just so it can be passed to an SVX method as a
        // nondet argument.  If we add support for untracked arguments, we can
        // just pass theParams by itself.
        public class AuthorizationCodeParamsMessage : SVX_MSG
        {
            public AuthorizationCodeParams theParams;
        }
        public class RPAuthenticationConclusion : SVX_MSG
        {
            public PrincipalHandle authenticatedClient;
            public string googleUsername;
        }

        public class Google_IdP : Participant
        {
            public Principal SVXPrincipal => googlePrincipal;
            private GoogleAuthorizationCodeGenerator authorizationCodeGenerator = new GoogleAuthorizationCodeGenerator();

            private Dictionary<Secret, AuthorizationCodeParams> authorizationCodeParamsDict = new Dictionary<Secret, AuthorizationCodeParams>();

            public string CodeEndpoint(PrincipalHandle client, string codeRequestStr)
            {
                var req = JsonConvert.DeserializeObject<AuthorizationCodeRequest>(codeRequestStr);
                authorizationCodeRequestStructure.Import(req,
                    // We don't know who produced the request.
                    PrincipalFacet.GenerateNew(SVXPrincipal),
                    client);

                // In reality, AuthenticateClient couldn't be done
                // synchronously, so both TokenEndpoint and AuthenticateClient
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

            IdPAuthenticationEntry AuthenticateClient(PrincipalHandle client)
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

            public IdPAuthenticationEntry SVX_ConcludeClientAuthentication(IdPAuthenticationEntry entry)
            {
                // TODO: Declare IdpSignedIn predicate here (or add to a dictionary).
                VProgram_API.AssumeActsFor(entry.authenticatedClient, GoogleUserPrincipal(entry.googleUsername));
                // Reuse the message... Should be able to get away with it.
                return entry;
            }

            public AuthorizationCodeResponse SVX_MakeAuthorizationCodeResponse(AuthorizationCodeRequest req, IdPAuthenticationEntry idpConc)
            {
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
                PrincipalHandle client = PrincipalFacet.GenerateNew(googlePrincipal);

                var req = JsonConvert.DeserializeObject<ValidationRequest>(validationRequestStr);
                validationRequestStructure.Import(req,
                    // Assume validation requests are not XSRF-able.
                    // TODO: Think more carefully about this.
                    client,
                    client);

                var paramsMsg = new AuthorizationCodeParamsMessage
                {
                    theParams = authorizationCodeParamsDict[req.authorizationCode]
                };

                var resp = SVX_Ops.Call(SVX_MakeValidationResponse, req, paramsMsg);

                validationResponseStructure.ExportDirectResponse(resp, client);
                return JsonConvert.SerializeObject(resp);
            }

            public ValidationResponse SVX_MakeValidationResponse(ValidationRequest req, AuthorizationCodeParamsMessage paramsMsg)
            {
                // As long as we're using the interim implementation of
                // AssumeValidSecret that assumes the parameters of equal
                // secrets are reference equal, it's critical that we don't do
                // anything that will introduce a contradiction.  With theParams
                // as nondet, we should be OK for now.
                var theParams = paramsMsg.theParams;
                // Comment out these 2 lines to see the verification fail.
                if (theParams.rpPrincipal != req.rpPrincipal)
                    throw new Exception("Authorization code RP mismatch");
                authorizationCodeGenerator.Verify(theParams, req.authorizationCode);
                return new ValidationResponse
                {
                    googleUsername = theParams.googleUsername
                };
            }
        }

        class StateParams
        {
            internal string sessionId;
        }
        class MattMerchant_Google_StateGenerator : SecretGenerator<StateParams>
        {
            protected override PrincipalHandle[] GetReaders(object theParams)
            {
                var params2 = (StateParams)theParams;
                return new PrincipalHandle[] { googlePrincipal, mattMerchantPrincipal,
                    PrincipalFacet.Of(mattMerchantPrincipal, params2.sessionId) };
            }

            protected override string RawGenerate(StateParams theParams)
            {
                return "mattmerchant_google_state:" + theParams.sessionId;
            }

            protected override void RawVerify(StateParams theParams, string secretValue)
            {
                if (secretValue != RawGenerate(theParams))
                    throw new ArgumentException();
            }
        }

        public class MattMerchant_RP : Participant
        {
            // XXX Definitely needs to be a parameter.
            public Principal SVXPrincipal => mattMerchantPrincipal;

            MattMerchant_Google_StateGenerator stateGenerator = new MattMerchant_Google_StateGenerator();

            public string LoginStart(PrincipalHandle client)
            {
                var req = new AuthorizationCodeRequest
                {
                    rpPrincipal = SVXPrincipal,
                    // XXX This cast is a little contrived.  Decide if we want
                    // to pass the client as a session ID or a facet or what.
                    state = stateGenerator.Generate(
                        new StateParams { sessionId = ((PrincipalFacet)client).id },
                        SVXPrincipal)
                };
                authorizationCodeRequestStructure.Export(req, client, googlePrincipal);
                return JsonConvert.SerializeObject(req);
            }

            public void LoginCallback(PrincipalHandle client, string idTokenResponseStr, Google_IdP idp)
            {
                var authorizationCodeResponse = JsonConvert.DeserializeObject<AuthorizationCodeResponse>(idTokenResponseStr);
                authorizationCodeResponseStructure.Import(authorizationCodeResponse,
                    // We don't know who produced the redirection.
                    PrincipalFacet.GenerateNew(SVXPrincipal),
                    client);

                var validationRequest = SVX_Ops.Call(SVX_MakeValidationRequest, authorizationCodeResponse);

                validationRequestStructure.Export(validationRequest, googlePrincipal, null);
                var validationRequestStr = JsonConvert.SerializeObject(validationRequest);

                var validationResponseStr = idp.ValidationEndpoint(validationRequestStr);

                var validationResponse = JsonConvert.DeserializeObject<ValidationResponse>(validationResponseStr);
                validationResponseStructure.ImportDirectResponse(validationResponse, googlePrincipal, SVXPrincipal);

                // SVX will automatically detect using message IDs that
                // validationResponse actually resulted from
                // authorizationCodeResponse and not merely another message with
                // the same SymT.  This is essential for us to establish the
                // relationship between authorizationCodeResponse.SVX_sender and
                // validationResponse.googleUsername.
                var conc = SVX_Ops.Call(SVX_SignInRP, authorizationCodeResponse, validationResponse);

                SVX_Ops.Certify(conc, LoginSafety, new Principal[] { googlePrincipal, SVXPrincipal });
                //SVX_Ops.Certify(conc, LoginXSRFPrevention, new Principal[] { });
                // AbandonAndCreateSession...
            }

            public ValidationRequest SVX_MakeValidationRequest(AuthorizationCodeResponse resp)
            {
                return new ValidationRequest
                {
                    authorizationCode = resp.authorizationCode,
                    rpPrincipal = SVXPrincipal  // Like in the original authorization code request.
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

            public static bool LoginSafety(RPAuthenticationConclusion conc)
            {
                var targets = new PrincipalHandle[3];
                targets[0] = googlePrincipal;
                targets[1] = mattMerchantPrincipal;
                targets[2] = GoogleUserPrincipal(conc.googleUsername);
                return VProgram_API.ActsForAny(conc.authenticatedClient, targets);
            }

            public static bool LoginXSRFPrevention(RPAuthenticationConclusion conc)
            {
                // TODO
#if false
                var targets = new PrincipalHandle[3];
                targets[0] = googlePrincipal;
                targets[1] = mattMerchantPrincipal;
                targets[2] = GoogleUserPrincipal(conc.googleUsername);
                return VProgram_API.ActsForAny(conc.authenticatedClient, targets);
#endif
                throw new NotImplementedException();
            }
        }

        [BCTOmitImplementation]
        static SVX2_Test_AuthorizationCodeFlow()
        {
            // In all cases, we only bother declaring the secret readers we
            // actually need for the protocol flow.  Maybe this is a bad habit.

            authorizationCodeRequestStructure = new MessageStructure<AuthorizationCodeRequest>();
            authorizationCodeRequestStructure.AddSecret(nameof(AuthorizationCodeRequest.state),
                // The sender (the client) gets implicitly added.
                (msg) => new PrincipalHandle[] { msg.rpPrincipal });

            authorizationCodeResponseStructure = new MessageStructure<AuthorizationCodeResponse>();
            authorizationCodeResponseStructure.AddSecret(nameof(AuthorizationCodeRequest.state),
                (msg) => new PrincipalHandle[] { });
            authorizationCodeResponseStructure.AddSecret(nameof(AuthorizationCodeResponse.authorizationCode),
                (msg) => new PrincipalHandle[] { googlePrincipal });

            validationRequestStructure = new MessageStructure<ValidationRequest>();
            validationRequestStructure.AddSecret(nameof(AuthorizationCodeResponse.authorizationCode),
                (msg) => new PrincipalHandle[] { });

            // Nothing interesting here.
            validationResponseStructure = new MessageStructure<ValidationResponse>();
        }

        [BCTOmitImplementation]
        public static void Test()
        {
            var idp = new Google_IdP();
            var rp = new MattMerchant_RP();

            var aliceIdP = PrincipalFacet.GenerateNew(googlePrincipal);
            var aliceRP = PrincipalFacet.GenerateNew(mattMerchantPrincipal);

            var codeRequestStr = rp.LoginStart(aliceRP);
            var codeResponseStr = idp.CodeEndpoint(aliceIdP, codeRequestStr);
            rp.LoginCallback(aliceRP, codeResponseStr, idp);  // Includes the validation server-to-server call
        }
    }
}
