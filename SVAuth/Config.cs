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

            /* Hostname the agent should use for requests to the platform to
             * manipulate sessions.  Normally "localhost".  Can be changed to
             * "localhost.fiddler" to see this traffic in Fiddler.  (Note, the
             * machine hostname probably will not work because it will result in
             * the platform seeing a different source address than the
             * loopback.)
             * http://docs.telerik.com/fiddler/Configure-Fiddler/Tasks/MonitorLocalTraffic */
            public string internalHostname;

            // The "SVAuth/platforms" string is hard-coded a bunch of places; no
            // point trying to make it configurable.
            public string platformRootUrl =>
                $"{scheme}://{hostname}:{port}/SVAuth/platforms/{platform.name}/";
            public string internalPlatformRootUrl =>
                $"{scheme}://{internalHostname}:{port}/SVAuth/platforms/{platform.name}/";
        }

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
        }

        // These are currently set in the config loader, not in config.json.
        // Harmless to expose them to the deserializer? ~ t-mattmc@microsoft.com 2016-06-01
        public string agentRootUrl =>
            $"{AgentSettings.scheme}://{WebAppSettings.hostname}:{AgentSettings.port}/";
        public string MainPageUrl =>
            WebAppSettings.platformRootUrl + "AllInOne." + WebAppSettings.platform.fileExtension;

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
