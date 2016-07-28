using Microsoft.AspNetCore.Routing;
using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using BytecodeTranslator.Diagnostics;
using Newtonsoft.Json.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Http;
using SVX;

namespace SVAuth.ServiceProviders.Yahoo
{
    public class YahooAppRegistration
    {
        public string clientID;
        public string clientSecret;
    }
    public class AuthenticationRequest : OpenID20.AuthenticationRequest
    {
        [JsonProperty("openid.ns.oauth")]
        public string openid__ns__oauth;
        [JsonProperty("openid.oauth.consumer")]
        public string openid__oauth__consumer;

        /*attribute exchange*/
        [JsonProperty("openid.ns.ax")]
        public string openid__ns__ax;
        [JsonProperty("openid.ax.mode")]
        public string openid__ax__mode;
        [JsonProperty("openid.ax.type.email")]
        public string openid__ax__type__email;
        [JsonProperty("openid.ax.type.fullname")]
        public string openid__ax__type__fullname;
        [JsonProperty("openid.ax.required")]
        public string openid__ax__required;
    }

    public class AuthenticationResponse : OpenID20.AuthenticationResponse
    {
        [JsonProperty("openid.oauth.request_token")]
        public string openid__oauth__request_token;
        [JsonProperty("openid.ax.value.email")]
        public string openid__ax__value__email;
        [JsonProperty("openid.ax.type.email")]
        public string openid__ax__type__email;
        [JsonProperty("openid.ax.value.fullname")]
        public string openid__ax__value__fullname;
        [JsonProperty("openid.ax.type.fullname")]
        public string openid__ax__type__fullname;
    }

    public class UserProfile : GenericAuth.UserProfile
    {
        public string Email;
        public string FullName;
        public string Identity;
    }
    public class Yahoo_RP: OpenID20.RelyingParty
    {
        public string SignatureValidationUrl;

        public Yahoo_RP(SVX.Principal rpPrincipal, string Yahoo_Endpoint, string return_to_uri1)
        : base(rpPrincipal, Yahoo_Endpoint, return_to_uri1)
        {
            BypassCertification = true;
            SignatureValidationUrl = Yahoo_Endpoint;
        }
        public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new Yahoo_RP(
                Config.config.rpPrincipal,
                "https://open.login.yahooapis.com/openid/op/auth",
                Config.config.agentRootUrl + "callback/Yahoo"               
                );
            routeBuilder.MapRoute("login/Yahoo", RP.Login_StartAsync);
            routeBuilder.MapRoute("callback/Yahoo", RP.Login_CallbackAsync);
        }
        public override OpenID20.AuthenticationRequest createAuthenticationRequest(SVX.PrincipalFacet client)
        {
            AuthenticationRequest AuthenticationRequest = new AuthenticationRequest();
            AuthenticationRequest.openid__mode = "checkid_setup";
            AuthenticationRequest.openid__identity = "http://specs.openid.net/auth/2.0/identifier_select";
            AuthenticationRequest.openid__claimed_id = "http://specs.openid.net/auth/2.0/identifier_select";
            AuthenticationRequest.openid__assoc_handle = "blah_blah";
            AuthenticationRequest.openid__return_to = return_to_uri;
            AuthenticationRequest.openid__ns__oauth = "http://specs.openid.net/extensions/oauth/1.0";
            AuthenticationRequest.openid__oauth__consumer = Config.config.AppRegistration.Yahoo.clientID;

            // Yahoo doesn't seem to support OpenID extensions, so the next line is commented out
            //AuthenticationRequest.openid__sreg__required = "email,fullname";
            //AuthenticationRequest.openid__sreg__policy_url = "http://a.com/foo.html";

            AuthenticationRequest.openid__ns__ax = "http://openid.net/srv/ax/1.0";
            AuthenticationRequest.openid__ax__mode = "fetch_request";
            AuthenticationRequest.openid__ax__type__email = "http://axschema.org/contact/email";  //"http://schema.openid.net/contact/email"; //
            AuthenticationRequest.openid__ax__type__fullname = "http://axschema.org/namePerson";
            AuthenticationRequest.openid__ax__required = "email,fullname";
            return AuthenticationRequest;
        }
        public override string marshalAuthenticationRequest(OpenID20.AuthenticationRequest AuthenticationRequest)
        {
            return IdP_OpenID20_Uri + "?" + Utils.ObjectToUrlEncodedString(AuthenticationRequest);
        }

        public override OpenID20.AuthenticationResponse verify_and_parse_AuthenticationResponse (HttpContext context)
        {
            //Signature validation
            var RawRequestUrl = SignatureValidationUrl + context.Request.QueryString.Value.Replace("openid.mode=id_res","openid.mode=check_authentication");
            var rawReq = new HttpRequestMessage(HttpMethod.Get, RawRequestUrl);
            var RawResponse = Utils.PerformHttpRequestAsync(rawReq).Result;
            if (RawResponse.StatusCode != System.Net.HttpStatusCode.OK)
                return null;
            //Parsing
            return (OpenID20.AuthenticationResponse)Utils.ObjectFromQuery(context.Request.Query, typeof(AuthenticationResponse));
        }

        public override GenericAuth.AuthenticationConclusion createConclusion(OpenID20.AuthenticationResponse inputMSG)
        {
            var AuthenticationResponse = (AuthenticationResponse)inputMSG;
            var AuthConclusion = new GenericAuth.AuthenticationConclusion();
            AuthConclusion.authenticatedClient = inputMSG.SVX_sender;
            var userProfile = new UserProfile();

            userProfile.UserID = inputMSG.openid__identity;
            userProfile.Identity = inputMSG.openid__identity;
            
            if (AuthenticationResponse.openid__signed.Contains("ax.type.email") && AuthenticationResponse.openid__signed.Contains("ax.value.email") &&
                AuthenticationResponse.openid__ax__type__email== "http://axschema.org/contact/email")
                userProfile.Email = AuthenticationResponse.openid__ax__value__email;
            
            if (AuthenticationResponse.openid__signed.Contains("ax.type.fullname") && AuthenticationResponse.openid__signed.Contains("ax.value.fullname") && 
                AuthenticationResponse.openid__ax__type__fullname == "http://axschema.org/namePerson")
                userProfile.FullName = AuthenticationResponse.openid__ax__value__fullname;

            AuthConclusion.userProfile = userProfile;
            return AuthConclusion;
        }
    }
}


