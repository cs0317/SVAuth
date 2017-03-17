using Microsoft.AspNetCore.Routing;

namespace SVAuth.ServiceProviders.Microsoft
{
    public class MicrosoftAzureADAppRegistration
    {
        public string appId; 
        public string appSecret;
    }
   
    public class MicrosoftAzureAD_RP : Microsoft_RP
    {
        public MicrosoftAzureAD_RP(SVX.Entity rpPrincipal, string client_id1 = null, string redierct_uri1 = null, string client_secret1 = null, string AuthorizationEndpointUrl1 = null, string TokenEndpointUrl1 = null, string stateKey = null)
        : base(rpPrincipal, client_id1, redierct_uri1, client_secret1, AuthorizationEndpointUrl1, TokenEndpointUrl1,stateKey)
        {
        }

       new public static void Init(RouteBuilder routeBuilder)
        {
            var RP = new Microsoft_RP(
                Config.config.rpPrincipal,
                Config.config.AppRegistration.MicrosoftAzureAD.appId,
                Config.config.agentRootUrl + "callback/MicrosoftAzureAD",
                Config.config.AppRegistration.MicrosoftAzureAD.appSecret,
                "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/authorize",
                "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/token",
           //"https://testingsts.azurewebsites.net/oauth2/authorize",
           //"https://testingsts.azurewebsites.net/oauth2/token",
                Config.config.stateSecretKey);
            routeBuilder.MapRoute("login/MicrosoftAzureAD", RP.Login_StartAsync);
            routeBuilder.MapRoute("callback/MicrosoftAzureAD", RP.AuthorizationCodeFlow_Login_CallbackAsync);
        }
    }
}


