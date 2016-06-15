using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SVX
{

    public class DLLServerUploader
    {
        public static string depdown_page = "Account/DepHandle";
        public static string dlldown_page = "Account/DllHandle";
        public static string methoddown_page = "Account/DownloadMethodRecord";
        public static string dllanddepUp_page = "Account/UploadDll";
        public static string methodup_page = "Account/UploadMethodRecord";
        public static string sha_parameter_name = "USER_SHA";
        public static string verify_page = "Account/Verify";

        public DLLServerUploader()
        {
        }

        public bool verify(string SymT)
        {
            string assertionFileName = "Assertion.cs";
            string assertionFilePath = Path.Combine(SVXSettings.settings.VProgramPath, assertionFileName);
            byte[] assertionData = Encoding.UTF8.GetBytes(VProgramGenerator.Assertion_cs);

            string programFileName = "Program.cs";
            string programFilePath = Path.Combine(SVXSettings.settings.VProgramPath, programFileName);
            byte[] programFileData = Encoding.UTF8.GetBytes(VProgramGenerator.Program_cs);

            // Generate post objects
            var body = new MultipartFormDataContent();
            // See if we can get away without specifying "application/octet-stream".
            // If we need to specify it, set a header on the ByteArrayContent.
            // ~ t-mattmc@microsoft.com 2016-06-03
            body.Add(new ByteArrayContent(assertionData), "file", assertionFileName);
            body.Add(new ByteArrayContent(programFileData), "file2", programFileName);

            string url = SVXSettings.settings.DLLServerAddress + verify_page + "?" + "SymT=" + SymT + "&token=" + System.Uri.EscapeDataString(SVXSettings.settings.Token);

            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = body;
            HttpResponseMessage webResponse = Utils.PerformHttpRequestAsync(request).Result;
            var content = webResponse.Content.Headers.ContentDisposition;
            return (content != null && content.FileName.Equals("verified.txt"));
        }

        public void uploadMethodRecord(string filePath, string sha)
        {
            byte[] data = File.ReadAllBytes(filePath);

            string fileName = Path.GetFileName(filePath);
            // Generate post objects
            var body = new MultipartFormDataContent();
            body.Add(new ByteArrayContent(data), "file", fileName);

            string url = SVXSettings.settings.DLLServerAddress + methodup_page + "?" + sha_parameter_name + "=" + sha + "&token=" + System.Uri.EscapeDataString(SVXSettings.settings.Token);

            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = body;
            Utils.PerformHttpRequestAsync(request).Wait();
        }

        public void uploadDllDep(string dllFilePath, string depFilePath, string sha)
        {
            byte[] dllData = File.ReadAllBytes(dllFilePath);
            byte[] depData = File.ReadAllBytes(depFilePath);

            string dllFileName = Path.GetFileName(dllFilePath);
            string depFileName = Path.GetFileName(depFilePath);

            uploadDllDepData(dllFileName, dllData, depFileName, depData, sha);
        }

        public void uploadDllDepData(string dllFileName, byte[] dllData, string depFileName, byte[] depData, string sha)
        {
            // Generate post objects
            var body = new MultipartFormDataContent();
            body.Add(new ByteArrayContent(dllData), "file", dllFileName);
            body.Add(new ByteArrayContent(depData), "file2", depFileName);

            string url = SVXSettings.settings.DLLServerAddress + dllanddepUp_page + "?" + sha_parameter_name + "=" + sha + "&token=" + System.Uri.EscapeDataString(SVXSettings.settings.Token);

            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = body;
            Utils.PerformHttpRequestAsync(request).Wait();
        }
    }

    public class DLLServerDownloader
    {
        public static string depdown_page = "Account/DepHandle";
        public static string dlldown_page = "Account/DllHandle";
        public static string methoddown_page = "Account/DownloadMethodRecord";
        public static string dllanddepUp_page = "Account/UploadDll";
        public static string methodup_page = "Account/UploadMethodRecord";
        public static string sha_parameter_name = "USER_SHA";
        public static string symt_parameter_name = "SymT";
        public static string verify_page = "Account/Verify";


        private static void downloadFile(string path, string url)
        {
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }

            HttpResponseMessage response = Utils.PerformHttpRequestAsync(new HttpRequestMessage(HttpMethod.Get, url)).Result;
            var content = response.Content;
            // This is pretty sloppy... we could stream, but I don't care. ~ t-mattmc@microsoft.com 2016-06-03
            File.WriteAllBytes(Path.Combine(path, content.Headers.ContentDisposition.FileName), content.ReadAsByteArrayAsync().Result);
        }

        public DLLServerDownloader()
        {
        }


        public static void downloadDLLandDep(string sha)
        {
            string path = Path.Combine(SVXSettings.settings.dllsFolder, sha);

            downloadFile(path, SVXSettings.settings.DLLServerAddress + depdown_page + "?" + sha_parameter_name + "=" + sha + "&token=" + System.Uri.EscapeDataString(SVXSettings.settings.Token));
            downloadFile(path, SVXSettings.settings.DLLServerAddress + dlldown_page + "?" + sha_parameter_name + "=" + sha + "&token=" + System.Uri.EscapeDataString(SVXSettings.settings.Token));

            if (Directory.Exists(path)) {
                string[] depfiles = Directory.GetFiles(path, "*.dep");

                if (depfiles.Length > 0)
                {
                    string dependentDLLs = File.ReadAllText(depfiles[0]);

                    string pattern = @"\\[A-Za-z0-9.]+\\[A-Za-z0-9.]*dll\n";
                    Regex rgx = new Regex(pattern);
                    foreach (Match match in rgx.Matches(dependentDLLs))
                    {
                        string matched_sha = match.Value.Substring(1).Split('\\')[0];

                        if (!Directory.Exists(Path.Combine(SVXSettings.settings.dllsFolder, matched_sha)))
                            downloadDLLandDep(matched_sha);
                    }
                }
            }
        }

        public static void downloadMethodRecord(string sha)
        {
            downloadFile(SVXSettings.settings.methodsFolder, SVXSettings.settings.DLLServerAddress + methoddown_page + "?" + sha_parameter_name + "=" + sha);
        }


        public static bool verify(string SymT)
        {
            string vfolder = Path.Combine(SVXSettings.settings.SVXFolderPath, "vprogram");
            downloadFile(vfolder, SVXSettings.settings.DLLServerAddress + verify_page + "?" + symt_parameter_name + "=" + SymT + "&token=" + System.Uri.EscapeDataString(SVXSettings.settings.Token));

            return true;
        }
    }}
