using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading.Tasks;
using SVX;

namespace SVAuth
{
    public static class SVX_Test_Secret
    {
        static readonly Entity idpPrincipal = Entity.Of("IdP");
        static readonly Entity rpPrincipal = Entity.Of("RP");

        static Entity IdPUserPrincipal(string username)
        {
            return Entity.Of("IdP:" + username);
        }

        class SSOSecretParams
        {
            // Corresponds to IdPUserPrincipal(username)
            internal string username;
        }
        class SSOSecretGenerator : SecretGenerator<SSOSecretParams>
        {
            protected override Principal[] GetReaders(object theParams)
            {
                return new Entity[] { idpPrincipal, rpPrincipal, IdPUserPrincipal(((SSOSecretParams)theParams).username),
                    // Uncomment to see the verification fail.
                    //Principal.Of("other")
                };
            }

            protected override string RawGenerate(SSOSecretParams theParams)
            {
                return "sso:(" + theParams.username + ")";
            }

            protected override void RawVerify(SSOSecretParams theParams, string secretValue)
            {
                if (RawGenerate(theParams) != secretValue)
                    throw new ArgumentException();
            }
        }

        public class SignInIdPReq : SVX_MSG
        {
            public string username;
            // I wonder if we can model the password as an SVX secret too.
            // Maybe, but it's not the point of using SVX.
            public string password;
        }
        public class SignInRPReq : SVX_MSG
        {
            public string username;
            public Secret ssoSecret;
        }
        public class AuthenticationConclusion : SVX_MSG
        {
            public Principal authenticatedClient;
            public string idpUsername;
        }

        public class IdP : Participant
        {
            public IdP(Entity principal) : base(principal) { }

            private SSOSecretGenerator ssoSecretGenerator = new SSOSecretGenerator();

            public SignInRPReq SignInIdP(SignInIdPReq req)
            {
                if (req.password != "password:" + req.username)
                    throw new ArgumentException();
                var userPrincipal = IdPUserPrincipal(req.username);
                // If this line is commented out, the check for whether it's OK
                // to send the secret to the client would fail, but this example
                // doesn't use export/import.
                VProgram_API.AssumeActsFor(req.SVX_sender, userPrincipal);
                var ssoSecretParams = new SSOSecretParams { username = req.username };
                var resp = new SignInRPReq {
                    username = req.username,
                    ssoSecret = ssoSecretGenerator.Generate(ssoSecretParams, SVX_Principal)
                };
                ssoSecretGenerator.Verify(ssoSecretParams, resp.ssoSecret);
                return resp;
            }
        }
        public class RP : Participant
        {
            public RP(Entity principal) : base(principal) { }

            public AuthenticationConclusion SignInRP(SignInRPReq req)
            {
                return new AuthenticationConclusion {
                    authenticatedClient = req.SVX_sender,
                    idpUsername = req.username
                };
            }

            public bool LoginSafety(AuthenticationConclusion conc)
            {
                var userPrincipal = IdPUserPrincipal(conc.idpUsername);
                VProgram_API.AssumeTrusted(idpPrincipal);
                VProgram_API.AssumeTrusted(rpPrincipal);
                VProgram_API.AssumeTrusted(userPrincipal);
                // BCT accepts this code but silently mistranslates it!
                //return VProgram_API.ActsForAny(conc.authenticatedClient,
                //    new PrincipalHandle[] { idpPrincipal, rpPrincipal, IdPUserPrincipal(conc.idpUsername) });
                var targets = new Principal[3];
                targets[0] = idpPrincipal;
                targets[1] = rpPrincipal;
                targets[2] = userPrincipal;
                return VProgram_API.ActsForAny(conc.authenticatedClient, targets);
            }
        }

        [BCTOmitImplementation]
        public static void Test()
        {
            var idp = new IdP(idpPrincipal);
            var rp = new RP(rpPrincipal);

            var aliceIdP = Channel.GenerateNew(idpPrincipal);
            var aliceRP = Channel.GenerateNew(rpPrincipal);

            var idpReq = new SignInIdPReq {
                username = "alice",
                password = "password:alice",
                SVX_sender = aliceIdP
            };
            var rpReq = SVX_Ops.Call(idp.SignInIdP, idpReq);

            // Imagine the SignInRPReq was signed by the IdP.
            SVX_Ops.TransferForTesting(rpReq, idpPrincipal, aliceRP);

            var conc = SVX_Ops.Call(rp.SignInRP, rpReq);
            SVX_Ops.Certify(conc, rp.LoginSafety);
        }
    }
}
