using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SVAuth.OIDC10
{
    /***********************************************************/
    /*               Messages between parties                  */
    /***********************************************************/

    public class AuthenticationRequest : OAuth20.AuthorizationRequest
    {
        public string response_mode = null;
        public string nonce = null;
        public string display = null;
        public string prompt = null;
        public string max_age = null;
        public string ui_locales = null;
        public string id_token_hint = null;
        public string login_hint = null;
        public string acr_values = null;
    }

    public class AuthenticationResponse : OAuth20.AuthorizationResponse
    {
    }

    public class TokenRequest : OAuth20.AccessTokenRequest
    {
    }

    public class TokenResponse : OAuth20.AccessTokenResponse
    {
        //////////////////////
    }
}
