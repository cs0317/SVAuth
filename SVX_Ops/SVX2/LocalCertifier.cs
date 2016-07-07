using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using SVXSettings = SVX.SVXSettings;
using Utils = SVX.Utils;
using System.Diagnostics;
using Newtonsoft.Json;
using System.Reflection;

namespace SVX2
{
    // Most of LocalCertifier is copy/paste from SVX1 VProgramGenerator.
    // Put the boring stuff in a separate file.

    static class LocalCertifier
    {
        internal static bool Certify(CertificationRequest c)
        {
            byte[] time = BitConverter.GetBytes(DateTime.UtcNow.ToBinary());
            byte[] key = Guid.NewGuid().ToByteArray();
            // Slashes would be a problem, so use URL-safe base 64.  .NET does
            // not seem to have a built-in function for it, so just do it
            // manually. :(
            string rand_folder = Utils.ToUrlSafeBase64String(time.Concat(key).ToArray());
            string tempVProgramPath = Path.Combine(SVXSettings.settings.VProgramPath, rand_folder);
            Console.WriteLine("Generating and verifying vProgram in: " + tempVProgramPath);

            try
            {
                Directory.CreateDirectory(SVXSettings.settings.VProgramPath);
                CreateTempVFolder(tempVProgramPath);
                File.WriteAllText(Path.Combine(tempVProgramPath, "vProgram", "Program.cs"),
                    new VProgramEmitter(c).GetSynthesizedPortion());

                return verify(tempVProgramPath);
            }
            finally
            {
                if (!SVXSettings.settings.KeepVPrograms)
                {
                    // Best effort
                    try
                    {
                        Directory.Delete(tempVProgramPath, true);
                    }
                    catch { }
                }
            }
        }

        private static void CreateTempVFolder(string tempVProgramPath)
        {
            // Note: tempVProgramPath is the equivalent of a solution.  It
            // contains project subdirectories "vProgram" and "SVAuth", because
            // .NET Core requires that DLLs be wrapped in their own project to
            // be referenced, and I had no luck with the "SVAuth" project as a
            // subdirectory of "vProgram". ~ t-mattmc@microsoft.com 2016-06-10

            // Copy the vProgram skeleton.
            // http://stackoverflow.com/a/58820
            // I like this because it involves the least code.
            Process copyProcess = new Process();
            copyProcess.StartInfo.UseShellExecute = false;
            copyProcess.StartInfo.FileName = @"C:\WINDOWS\system32\xcopy.exe";
            // vProgram-skeleton is relative to working directory, assumed to be
            // SVAuth project root (not solution root).
            copyProcess.StartInfo.Arguments = @"/E /I ..\vProgram-skeleton " + tempVProgramPath;
            copyProcess.Start();
            copyProcess.WaitForExit();
            if (copyProcess.ExitCode != 0)
                throw new Exception("xcopy of vProgram skeleton failed");

            var svauthPath = Path.GetDirectoryName(Directory.GetCurrentDirectory());

            // Simple string substitutor.  If you know a better library for
            // this, be my guest. ~ t-mattmc@microsoft.com 2016-06-14
            var substitutions = new Dictionary<string, string> {
                { "SVAUTH_PATH", svauthPath },
                // This definitely needs escaping of backslashes.  May as well
                // do the real thing rather than hard-coding it.
                { "SVAUTH_PATH_JSON", JsonConvert.ToString(svauthPath) },
                // For now, we build against the .NET Core runtime being used by
                // the certifier.  Reconsider when we update the certification
                // server.  Anyone know a proper API to get this?
                { "DOTNET_CORE_LIBPATH", Path.GetDirectoryName(typeof(object).GetTypeInfo().Assembly.Location) }
            };
            foreach (var relativePath in new List<string> { "global.json", "vProgram/run.bat" })
            {
                string path = Path.Combine(tempVProgramPath, relativePath);
                string content = File.ReadAllText(path);
                foreach (var kvp in substitutions)
                {
                    content = content.Replace("@" + kvp.Key + "@", kvp.Value);
                }
                File.WriteAllText(path, content);
            }
        }
        private static bool verify(string tempVProgramPath)
        {
            Process process = new Process();
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.WorkingDirectory = Path.Combine(tempVProgramPath, "vProgram");
            process.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
            process.StartInfo.Arguments = "/c run.bat";
            process.StartInfo.RedirectStandardOutput = true;
            // process.StartInfo.Environment is initialized to the current
            // process's environment, so the subprocess inherits anything we
            // don't change.
            // http://stackoverflow.com/a/14582921
            // https://github.com/dotnet/corefx/blob/2ff9b2a1e367a9694af6bdaf9856ea12f9ae13cd/src/System.Diagnostics.Process/src/System/Diagnostics/ProcessStartInfo.cs#L88
            process.StartInfo.Environment.Add("POIROT_ROOT", SVXSettings.settings.PoirotRoot);
            process.Start();

            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Console.Write(output);  // Ideally this would be streamed. ~ t-mattmc@microsoft.com 2016-06-06

            if (output.IndexOf("Program has no bugs") > 0)
                return true;
            else
                return false;
        }
    }
}
