using System;
using System.Collections.Concurrent;
using System.Net.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using SVXSettings = SVX.SVXSettings;

namespace SVX
{

    // cache interface
    interface ICache
    {
        bool TryAdd(CertificationRequest key, Func<CertificationRequest, bool> valueFactory);
        void InitCache();
    }

    // a file-based certification request caching class
    // when SVX starts, the file cache do the followings
    // 1. loads existing certification requests from the cache directory
    // 2. adds each certification request to the memory cache (implemented by ConcurrentDictionary)
    class FileCache : ICache
    {
        // use ConcurrentDictionary as memory cache in addition to file-based cache
        // we store sha256 hash of a verified cert request in the memory
        private static ConcurrentDictionary<string, bool> certificationCache = new ConcurrentDictionary<string, bool>();
        private string agentHostname = "localhost";

        // returns the certification result for a certificationRequest
        //  
        // when a certification request needs to be verified
        // 1. check whether the cert request has been verified before using memory cache
        // if the request has not been verified, write the cert request to the cache folder
        // 2. verify the cert request and add to memory cache 
        public bool TryAdd(CertificationRequest certRequest, Func<CertificationRequest, bool> verifyFunction)
        {
            // If we have the certRequest in certificationCache, return true immediately
            // because we only cache verified certRequests
            // force using Windows-style line ending in cache files
            string certStr = SerializationUtils.ReflectObject(certRequest).ToString()
                .Replace(Environment.NewLine, "\r\n")
                .Replace(this.agentHostname, SVXSettings.settings.canocialagentHostname);

            string certHash = SerializationUtils.Hash(certStr);

            Console.WriteLine("Hash of the theorem to verify {0}", certHash);

            if (certificationCache.ContainsKey(certHash))
            {
                return true;
            }

            // When we don't have the certRequest in certificationCache, perform verification
            bool certResult = verifyFunction(certRequest);
            // store the serialized cert request to this directory, 
            // either a "cache" folder if the cert request is verified,
            // or a "failed-certs" folder if the cert request is not verified
            string certResultStoreFolderPath = certResult ? SVXSettings.settings.SVXCacheFolderPath : SVXSettings.settings.SVXCacheFailedCertsFolderPath;
            try
            {
                if (certResult == true)
                {  // If the certRequest is verified, add it to the memory cache 
                    certificationCache.TryAdd(certHash, certResult);
                }
                // store serialized cert request to directory
                // file format: {SHA256 hash of certRequest}.json
                string fileName = String.Format(@"{0}\{1}.json", certResultStoreFolderPath, certHash);
                File.WriteAllBytes(fileName, Encoding.UTF8.GetBytes(certStr));
            }
            catch (Exception e)
            {
                Console.WriteLine("Caching failed! {0}", e);
            }

            // Finally return the certResult
            return certResult;

        }

        public void InitCache()
        {
            // load agent hostname from config file
            JObject config = JObject.Parse(File.ReadAllText("common/agent_config.json"));
            this.agentHostname = (string)config.SelectToken("AgentSettings")["agentHostname"];

            // create the cache directory and the directory to store failed cert requests if not exists
            // CreateDirectory will NOT overwrite an existing cache folder (see its document)
            // https://msdn.microsoft.com/en-us/library/07wt70x2(v=vs.110).aspx
            Directory.CreateDirectory(SVXSettings.settings.SVXCacheFolderPath);
            Directory.CreateDirectory(SVXSettings.settings.SVXCacheFailedCertsFolderPath);
            // loads previous certification requests from a directory to the certificationCache
            this.ProcessDirectory(SVXSettings.settings.SVXCacheFolderPath);
        }

        // process all files in the directory passed in (non-recursive)
        // https://msdn.microsoft.com/en-us/library/07wt70x2(v=vs.110).aspx
        public void ProcessDirectory(string targetDirectory)
        {
            // Process the list of files found in the directory.
            string[] fileEntries = Directory.GetFiles(targetDirectory);
            Console.WriteLine("Loading cached certificate requests from {0}...", targetDirectory);
            int numLoadedCerts = 0;
            foreach (string fileName in fileEntries)
            {
                if (ProcessFile(fileName))
                {
                    numLoadedCerts += 1;
                }
            }
            Console.WriteLine("Loaded {0} certificate requests", numLoadedCerts);
        }

        // load certified requests
        public bool ProcessFile(string path)
        {
            // Load cached cert requests
            try
            {
                byte[] certBytes = File.ReadAllBytes(path);
                string certHash;

                /* TODO: This is a good sanity check, but before we implement the remote certification server, we need to manually add hash value, and cannot do this check
                                certHash = SerializationUtils.Hash(certBytes);
                */
                /* Instead, we do the following */
                int pos = path.IndexOf(".json");
                certHash = path.Substring(pos - 64, 64);
                Console.WriteLine("Cached hash value {0}", certHash);

                // since we only store certified requests, we don't need to re-verify here
                return certificationCache.TryAdd(certHash, true);
            }
            catch (Exception e)
            {
                Console.WriteLine("Cannot deserialize {0}, skipping.. {1}", path, e);
            }
            return false;
        }

    }
}
