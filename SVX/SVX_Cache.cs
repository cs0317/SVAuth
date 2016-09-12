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
        // we store sha256 hash of a verified cert request in the memory
        private static ConcurrentDictionary<string, bool> certificationCache = new ConcurrentDictionary<string, bool>();

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
            string certStr = SerializationUtils.ReflectObject(certRequest).ToString();
            string certHash = SerializationUtils.Hash(certStr);

            if (certificationCache.ContainsKey(certHash)) {
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
                    certificationCache.TryAdd(certHash, certResult);
                    // add to cache directory
                    // file format: {SHA256 hash of certRequest}.json
                    string fileName = String.Format(@"{0}\{1}.json", cacheLocation, certHash);
                    File.WriteAllText(fileName, certStr);
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
                string certStr = File.ReadAllText(path);
                string certHash = SerializationUtils.Hash(certStr);
                // since we only store certified requests, we don't need to re-verify here
                return certificationCache.TryAdd(certHash, true);
            } catch (Exception e)
            {
                Console.WriteLine("Cannot deserialize {0}, skipping.. {1}", path, e);
            }
            return false;
        }

    }
}