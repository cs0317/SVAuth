using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace SVAuth
{
    public class Config
    {
        // Ideally we'd like this to be read-only, but it's not worth writing a
        // lot of boilerplate code just to ensure that. ~ t-mattmc@microsoft.com 2016-06-01
        public static Config config;

        // Individual setting groups:

        public SVX.SVXSettings SVXSettings;

        public WebAppSettings_ WebAppSettings;
        public class WebAppSettings_
        {
            public string hostname;
            public string scheme;
            public int port;
            public PlatformSettings platform;
            public class PlatformSettings
            {
                public string name;
                public string fileExtension;
            }

            // The "SVAuth/platforms" string is hard-coded a bunch of places; no
            // point trying to make it configurable.
            public string platformRootUrl =>
                $"{scheme}://{hostname}:{port}/SVAuth/platforms/{platform.name}/";
        }

        // http://docs.telerik.com/fiddler/Configure-Fiddler/Tasks/MonitorLocalTraffic
        // SVAuth will not work if this option is enabled and Fiddler is not running.
        public bool sendInternalTrafficViaFiddler = false;
        public string internalPlatformHostname =>
            sendInternalTrafficViaFiddler ? "localhost.fiddler" : "localhost";

        public AgentSettings_ AgentSettings;
        public class AgentSettings_
        {
            // NOTE: This setting is not automatically passed to the platform.
            // The platform files have to be edited manually to change it.
            public string scheme = "http";
            public int port;
        }

        public SessionIDCookieProperties_ SessionIDCookieProperties;
        public class SessionIDCookieProperties_
        {
            public string domain;
            public bool persistent;
        }

        public AppRegistration_ AppRegistration;
        public class AppRegistration_
        {
            public ServiceProviders.Facebook.FBAppRegistration Facebook;
            public ServiceProviders.Microsoft.MSAppRegistration Microsoft;
            public ServiceProviders.Google.GGAppRegistration Google;
            public ServiceProviders.Yahoo.YahooAppRegistration Yahoo;
        }

        // The same key is used for all OAuth 2.0 IdPs, but the state value will
        // be different depending on the IdP.
        public string stateSecretKey;

        public string agentRootUrl =>
            $"{AgentSettings.scheme}://{WebAppSettings.hostname}:{AgentSettings.port}/";
        public string internalPlatformRootUrl =>
            $"{WebAppSettings.scheme}://{internalPlatformHostname}:{WebAppSettings.port}/" +
            $"SVAuth/platforms/{WebAppSettings.platform.name}/";
        public string MainPageUrl =>
            WebAppSettings.platformRootUrl + "AllInOne." + WebAppSettings.platform.fileExtension;
        public SVX.Principal rpPrincipal => SVX.Principal.Of(WebAppSettings.hostname);

        // Configuration loader:

        public static void Init()
        {
            // XXX Assumes that the working directory is the project root.  (The
            // original Auth.JS had the same limitation.)  We could consider
            // finding the project root via Environment.GetCommandLineArgs()[0].
            // ~ t-mattmc@microsoft.com 2016-06-01
            config = JsonConvert.DeserializeObject<Config>(File.ReadAllText("config.json"));

            SVX.SVXSettings.settings = config.SVXSettings;
        }
    }
}
