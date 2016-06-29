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
        }

        public AuthJSSettings_ AuthJSSettings;
        public class AuthJSSettings_
        {
            public string scheme;
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
        }

        // These are currently set in the config loader, not in config.json.
        // Harmless to expose them to the deserializer? ~ t-mattmc@microsoft.com 2016-06-01
        public string rootUrl;
        public string MainPageUrl;

        // Configuration loader:

        public static void Init()
        {
            // XXX Assumes that the working directory is the project root.  (The
            // original Auth.JS had the same limitation.)  We could consider
            // finding the project root via Environment.GetCommandLineArgs()[0].
            // ~ t-mattmc@microsoft.com 2016-06-01
            config = JsonConvert.DeserializeObject<Config>(File.ReadAllText("config.json"));
            config.rootUrl = config.AuthJSSettings.scheme + "://" + config.WebAppSettings.hostname + ':' + config.AuthJSSettings.port + '/';
            config.MainPageUrl = "http://" + config.WebAppSettings.hostname + ':' + config.WebAppSettings.port + '/' + "SVAuth/platforms/aspx/AllInOne.aspx";

            SVX.SVXSettings.settings = config.SVXSettings;
        }
    }
}
