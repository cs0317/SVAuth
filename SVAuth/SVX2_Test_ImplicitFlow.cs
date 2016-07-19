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
    public static class SVX2_Test_ImplicitFlow
    {
        static readonly Principal googlePrincipal = Principal.Of("Google");
        static readonly Principal mattMerchantPrincipal = Principal.Of("MattMerchant");

        static Principal GoogleUserPrincipal(string username)
        {
            return Principal.Of("Google:" + username);
        }

        public class IdTokenBody : SVX_MSG
        {
            // Corresponds to GoogleUserPrincipal(username)
            public string username;
            public Principal rpPrincipal;
        }

        public class GoogleIdTokenVerifier : MessagePayloadSecretGenerator<IdTokenBody>
        {
            // XXX Eventually this needs to be a parameter.
            protected override PrincipalHandle Signer => googlePrincipal;

            protected override PrincipalHandle[] GetReaders(object theParams)
            {
                var body = (IdTokenBody)theParams;
                return new Principal[] {
                    // Comment this to get an internal error during secret generation.
                    googlePrincipal,
                    // Comment either of these to see the secret export check fail.
                    body.rpPrincipal,
                    GoogleUserPrincipal(body.username),
                    // Uncomment to see the verification fail.
                    //Principal.Of("other")
                };
            }

            protected override IdTokenBody RawExtractUnverified(string secretValue)
            {
                throw new NotImplementedException();
            }

            protected override string RawGenerate(IdTokenBody theParams)
            {
                // Pretend we don't have Google's private key and can't generate.
                throw new NotImplementedException();
            }

            protected override IdTokenBody RawVerifyAndExtract(string secretValue)
            {
                return JsonConvert.DeserializeObject<IdTokenBody>(secretValue);
            }
        }

        class GoogleIdTokenGenerator : GoogleIdTokenVerifier
        {
            protected override string RawGenerate(IdTokenBody theParams)
            {
                // Nothing actually secret. :)
                return JsonConvert.SerializeObject(theParams);
            }
        }

        static MessageStructure<IdTokenRequest> idTokenRequestStructure;
        static MessageStructure<IdTokenResponse> idTokenResponseStructure;

        public class IdTokenRequest : SVX_MSG
        {
            public Principal rpPrincipal;
            public Secret state;
        }
        public class IdTokenResponse : SVX_MSG
        {
            public PayloadSecret<IdTokenBody> idToken;
            public Secret state;
        }

        public class IdPAuthenticationEntry : SVX_MSG
        {
            public PrincipalHandle authenticatedClient;
            public string googleUsername;
        }
        public class RPAuthenticationConclusion : SVX_MSG
        {
            public PrincipalHandle authenticatedClient;
            public string googleUsername;
        }

        public class Google_IdP : Participant
        {
            public Principal SVXPrincipal => googlePrincipal;
            private GoogleIdTokenGenerator idTokenGenerator = new GoogleIdTokenGenerator();

            public string TokenEndpoint(PrincipalHandle client, string idTokenRequestStr)
            {
                var req = JsonConvert.DeserializeObject<IdTokenRequest>(idTokenRequestStr);
                idTokenRequestStructure.Import(req,
                    // We don't know who produced the request.
                    PrincipalFacet.GenerateNew(SVXPrincipal),
                    client);

                // In reality, AuthenticateClient couldn't be done
                // synchronously, so both TokenEndpoint and AuthenticateClient
                // would be broken into a start and a callback.
                var idpConc = AuthenticateClient(client);

                var resp = SVX_Ops.Call(SVX_MakeIdTokenResponse, req, idpConc);

                idTokenResponseStructure.Export(resp, client, req.rpPrincipal);
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

            public IdTokenResponse SVX_MakeIdTokenResponse(IdTokenRequest req, IdPAuthenticationEntry idpConc)
            {
                // Put this in a separate SVX method so "body" gets an active SymT.
                var body = SVX_Ops.Call(SVX_MakeIdTokenBody, req, idpConc);
                return new IdTokenResponse
                {
                    idToken = idTokenGenerator.Generate(body, SVXPrincipal),  // sign the token
                    state = req.state
                };
            }

            public IdTokenBody SVX_MakeIdTokenBody(IdTokenRequest req, IdPAuthenticationEntry idpConc)
            {
                return new IdTokenBody
                {
                    rpPrincipal = req.rpPrincipal,
                    username = idpConc.googleUsername
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
                var req = new IdTokenRequest
                {
                    rpPrincipal = SVXPrincipal,
                    // XXX This cast is a little contrived.  Decide if we want
                    // to pass the client as a session ID or a facet or what.
                    state = stateGenerator.Generate(
                        new StateParams { sessionId = ((PrincipalFacet)client).id },
                        SVXPrincipal)
                };
                idTokenRequestStructure.Export(req, client, googlePrincipal);
                return JsonConvert.SerializeObject(req);
            }

            public void LoginCallback(PrincipalHandle client, string idTokenResponseStr)
            {
                var idTokenResponse = JsonConvert.DeserializeObject<IdTokenResponse>(idTokenResponseStr);
                idTokenResponseStructure.Import(idTokenResponse,
                    // We don't know who produced the redirection.
                    PrincipalFacet.GenerateNew(SVXPrincipal),
                    client);

                var conc = SVX_Ops.Call(SVX_SignInRP, idTokenResponse);

                SVX_Ops.Certify(conc, LoginSafety, new Principal[] { googlePrincipal, SVXPrincipal });
                //SVX_Ops.Certify(conc, LoginXSRFPrevention, new Principal[] { });
                // AbandonAndCreateSession...
            }
            public RPAuthenticationConclusion SVX_SignInRP(IdTokenResponse resp)
            {
                // Comment out these 2 lines to see the verification fail.
                if (resp.idToken.theParams.rpPrincipal != SVXPrincipal)
                    throw new Exception("IdTokenResponse was not issued to this RP.");
                return new RPAuthenticationConclusion {
                    authenticatedClient = resp.SVX_sender,
                    googleUsername = resp.idToken.theParams.username
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
        static SVX2_Test_ImplicitFlow()
        {
            idTokenRequestStructure = new MessageStructure<IdTokenRequest>();
            idTokenRequestStructure.AddSecret(nameof(IdTokenRequest.state),
                // The sender (the client) gets implicitly added.
                // It doesn't matter whether we add the IdP here.  Convention?
                (msg) => new PrincipalHandle[] { msg.rpPrincipal });

            idTokenResponseStructure = new MessageStructure<IdTokenResponse>();
            idTokenResponseStructure.AddSecret(nameof(IdTokenRequest.state),
                // We're not passing the state along further, so we don't have to declare any readers.
                (msg) => new PrincipalHandle[] { });
            idTokenResponseStructure.AddMessagePayloadSecret(nameof(IdTokenResponse.idToken),
                (msg) => new PrincipalHandle[] { },
                new GoogleIdTokenVerifier(),
                true);
        }

        [BCTOmitImplementation]
        public static void Test()
        {
            var idp = new Google_IdP();
            var rp = new MattMerchant_RP();

            var aliceIdP = PrincipalFacet.GenerateNew(googlePrincipal);
            var aliceRP = PrincipalFacet.GenerateNew(mattMerchantPrincipal);

            var idTokenRequestStr = rp.LoginStart(aliceRP);
            var idTokenResponseStr = idp.TokenEndpoint(aliceIdP, idTokenRequestStr);
            rp.LoginCallback(aliceRP, idTokenResponseStr);
        }
    }
}
