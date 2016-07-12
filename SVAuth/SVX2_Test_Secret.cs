using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading.Tasks;
using SVX2;

namespace SVAuth
{
    public static class SVX2_Test_Secret
    {
        static readonly Principal idpPrincipal = Principal.Of("IdP");
        static readonly Principal rpPrincipal = Principal.Of("RP");

        static Principal IdPUserPrincipal(string username)
        {
            return Principal.Of("IdP:" + username);
        }

        class SSOSecretParams
        {
            // Corresponds to IdPUserPrincipal(username)
            internal string username;
        }
        class SSOSecretGenerator : SecretGenerator/*<SSOSecretParams>*/
        {
            protected override PrincipalHandle[] GetReaders(object/*SSOSecretParams*/ theParams)
            {
                return new Principal[] { idpPrincipal, rpPrincipal, IdPUserPrincipal(((SSOSecretParams)theParams).username),
                    // Uncomment to see the verification fail.
                    //Principal.Of("other")
                };
            }

            protected override string RawGenerate(object/*SSOSecretParams*/ theParams)
            {
                return "sso:(" + ((SSOSecretParams)theParams).username + ")";
            }

            protected override bool RawVerify(object/*SSOSecretParams*/ theParams, string secretValue)
            {
                return RawGenerate(theParams) == secretValue;
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
            public PrincipalHandle authenticatedClient;
            public string idpUsername;
        }

        public class IdP : Participant
        {
            public Principal SVXPrincipal => idpPrincipal;
            private SSOSecretGenerator ssoSecretGenerator = new SSOSecretGenerator();

            public SignInRPReq SignInIdP(SignInIdPReq req)
            {
                if (req.password != "password:" + req.username)
                    throw new ArgumentException();
                var userPrincipal = IdPUserPrincipal(req.username);
                // If this line is commented out, the check for whether it's OK
                // to send the secret to the client should fail, but that check
                // isn't implemented yet.
                VProgram_API.AssumeActsFor(req.sender, userPrincipal);
                var ssoSecretParams = new SSOSecretParams { username = req.username };
                var resp = new SignInRPReq {
                    username = req.username,
                    ssoSecret = ssoSecretGenerator.Generate(ssoSecretParams)
                };
                VProgram_API.Assert(ssoSecretGenerator.Verify(ssoSecretParams, resp.ssoSecret));
                return resp;
            }
        }
        public class RP : Participant
        {
            public Principal SVXPrincipal => rpPrincipal;

            public AuthenticationConclusion SignInRP(SignInRPReq req)
            {
                return new AuthenticationConclusion {
                    authenticatedClient = req.sender,
                    idpUsername = req.username
                };
            }
        }

        public static bool LoginSafety(AuthenticationConclusion conc) {
            // BCT accepts this code but silently mistranslates it!
            //return VProgram_API.ActsForAny(conc.authenticatedClient,
            //    new PrincipalHandle[] { idpPrincipal, rpPrincipal, IdPUserPrincipal(conc.idpUsername) });
            var targets = new PrincipalHandle[3];
            targets[0] = idpPrincipal;
            targets[1] = rpPrincipal;
            targets[2] = IdPUserPrincipal(conc.idpUsername);
            return VProgram_API.ActsForAny(conc.authenticatedClient, targets);
        }

        [BCTOmitImplementation]
        public static void Test()
        {
            var idp = new IdP();
            var rp = new RP();

            var aliceIdP = PrincipalFacet.GenerateNew(idpPrincipal);
            var aliceRP = PrincipalFacet.GenerateNew(rpPrincipal);

            var idpReq = new SignInIdPReq {
                username = "alice",
                password = "password:alice",
                sender = aliceIdP
            };
            var rpReq = SVX_Ops.Call(idp.SignInIdP, idpReq);

            // Imagine the SignInRPReq was signed by the IdP.
            SVX_Ops.Transfer(rpReq, idpPrincipal, aliceRP);

            var conc = SVX_Ops.Call(rp.SignInRP, rpReq);
            SVX_Ops.Certify(conc, LoginSafety, new Principal[] { idpPrincipal, rpPrincipal });
        }
    }
}
