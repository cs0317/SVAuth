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
        bool GetOrAdd(CertificationRequest key, Func<CertificationRequest, bool> valueFactory);
        object InitCache();
    }

    // a file-based certification request caching class
    // when SVX starts, the file cache do the followings
    // 1. loads existing certification requests from the cache directory
    // 2. verifies each certification request
    // 3. adds each certification request to the memory cache (implemented by ConcurrentDictionary)
    class FileCache: ICache
    {
        public FileCache(Func<CertificationRequest, bool> verifyFunctionFactory) {
            // initially, all certification requests are verified by a verifyFunctionFactory,
            // e.g., a LocalCertifier.Certify
            verifyFunction = verifyFunctionFactory;
        }

        // use ConcurrentDictionary as memory cache in addition to file-based cache
        private static ConcurrentDictionary<CertificationRequest, bool> certificationCache = new ConcurrentDictionary<CertificationRequest, bool>();
        // past certification requests are stored in this folder
        private static string cacheLocation = SVXSettings.settings.SVXCacheFolderPath;
        // certification verification function
        private Func<CertificationRequest, bool> verifyFunction;

        // when a certification request needs to be verified
        // 1. check whether the cert request has been verified before using memory cache
        // if the request has not been verified, write the cert request to the cache folder
        // 2. verify the cert request and add to memory cache 
        public bool GetOrAdd(CertificationRequest certRequest, Func<CertificationRequest, bool> verifyFunction)
        {
            // TODO(pmc): catch I/O exceptions
            if (! certificationCache.ContainsKey(certRequest)){
                // write to file
                var jsonStr = SerializationUtils.ReflectObject(certRequest).ToString();
                var hash = SerializationUtils.Hash(jsonStr);
                string fileName = String.Format(@"{0}\{1}.json", cacheLocation, hash);
                File.WriteAllText(fileName, SerializationUtils.ReflectObject(certRequest).ToString());
            }
            return certificationCache.GetOrAdd(certRequest, verifyFunction);
        }

        public InitCache()
        {
            // loads previous certification requests from a directory to the certificationCache
            this.ProcessDirectory(cacheLocation);
        }

        // https://msdn.microsoft.com/en-us/library/07wt70x2(v=vs.110).aspx
        // process all files in the directory passed in (non-recursive)
        public void ProcessDirectory(string targetDirectory)
        {
            // Process the list of files found in the directory.
            string[] fileEntries = Directory.GetFiles(targetDirectory);
            foreach (string fileName in fileEntries)
                ProcessFile(fileName);
        }

        // certify each certification request file
        public void ProcessFile(string path)
        {
            JObject jObj = JObject.Parse(File.ReadAllText(path));
            CertificationRequest certRequest = SerializationUtils.UnreflectObject<CertificationRequest>(jObj);
            certificationCache.GetOrAdd(certRequest, verifyFunction(certRequest));
        }

    }
}