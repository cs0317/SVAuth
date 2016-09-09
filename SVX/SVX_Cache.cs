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
    class FileCache: ICache
    {
        // use ConcurrentDictionary as memory cache in addition to file-based cache
        private static ConcurrentDictionary<CertificationRequest, bool> certificationCache = new ConcurrentDictionary<CertificationRequest, bool>();
        
        // past certification requests are stored in this folder
        private static string cacheLocation = SVXSettings.settings.SVXCacheFolderPath;

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
            if (certificationCache.ContainsKey(certRequest)) {
                return true;
            }

            // When we don't have the certRequest in certificationCache, perform verification
            bool certResult = verifyFunction(certRequest);
            // If the certRequest is verified, add it to the memory cache and the disk cache
            if (certResult == true)
            {
                try
                {
                    // add to memory cache
                    certificationCache.TryAdd(certRequest, certResult);
                    // add to cache directory
                    // file format: {SHA256 hash of certRequest}.json
                    var jsonStr = SerializationUtils.ReflectObject(certRequest).ToString();
                    var hash = SerializationUtils.Hash(jsonStr);
                    string fileName = String.Format(@"{0}\{1}.json", cacheLocation, hash);
                    File.WriteAllText(fileName, SerializationUtils.ReflectObject(certRequest).ToString());
                } catch (Exception e)
                {
                    Console.WriteLine("Caching failed! {0}", e);
                }
            }

            // Finally return the certResult
            return certResult;

        }

        public void InitCache()
        {
            // create the cache directory if not exists
            // CreateDirectory will NOT overwrite an existing cache folder (see its document)
            // https://msdn.microsoft.com/en-us/library/07wt70x2(v=vs.110).aspx
            Directory.CreateDirectory(cacheLocation);
            // loads previous certification requests from a directory to the certificationCache
            this.ProcessDirectory(cacheLocation);
        }

        // process all files in the directory passed in (non-recursive)
        // https://msdn.microsoft.com/en-us/library/07wt70x2(v=vs.110).aspx
        public void ProcessDirectory(string targetDirectory)
        {
            // Process the list of files found in the directory.
            string[] fileEntries = Directory.GetFiles(targetDirectory);
            foreach (string fileName in fileEntries)
                ProcessFile(fileName);
        }

        // load certified requests
        public void ProcessFile(string path)
        {
            // Workaround for Newtonsoft deserialization problem
            // If we can't deserialize a cached cert request, we just skip it and verify it at runtime.
            try
            {
                JObject jObj = JObject.Parse(File.ReadAllText(path));
                CertificationRequest certRequest = SerializationUtils.UnreflectObject<CertificationRequest>(jObj);
                // since we only store certified requests, we don't need to re-verify here
                certificationCache.TryAdd(certRequest, true);
            } catch (Exception e)
            {
                Console.WriteLine("Exception {0}", e);
            }
        }

    }
}