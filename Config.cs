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
            //public ServiceProviders.Microsoft.MSAppRegistration Microsoft;
        }

        // These are currently set in the config loader, not in config.json.
        // Harmless to expose them to the deserializer? ~ Matt 2016-06-01
        public string rootUrl;
        public string MainPageUrl;

        // Ideally we'd like this to be read-only, but it's not worth writing a
        // lot of boilerplate code just for that. ~ Matt 2016-06-01
        public static Config config;

        public static void Init()
        {
            // XXX Assumes that the working directory is the project root.  (The
            // original Auth.JS had the same limitation.)  We could consider
            // finding the project root via Environment.GetCommandLineArgs()[0].
            // ~ Matt 2016-06-01
            config = JsonConvert.DeserializeObject<Config>(File.ReadAllText("config.json"));
            config.rootUrl = config.AuthJSSettings.scheme + "://" + config.WebAppSettings.hostname + ':' + config.AuthJSSettings.port + '/';
            config.MainPageUrl = "http://" + config.WebAppSettings.hostname + ':' + config.WebAppSettings.port + '/' + "Auth.JS/platforms/aspx/AllInOne.aspx";
        }
    }
}
