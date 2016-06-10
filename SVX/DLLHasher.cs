using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Reflection;
using System.Xml.Linq;

namespace SVX
{
    public class DLLHasher
    {
        public string defaultSHA = "0000000000000000000000000000000000000000";

        public DLLHasher()
        {
        }

        public byte[] GenerateHash(string path, string name)
        {
            string depPath = Path.Combine(path, name + ".dep");
            string dllPath = Path.Combine(path, name + ".dll");
            byte[] fileInByte = File.ReadAllBytes(depPath);
            byte[] fileIndllBytes = File.ReadAllBytes(dllPath);
            return GenerateHash(fileInByte, fileIndllBytes);
        }

        public string GenerateHashInHexStr(byte[] fileInByte, byte[] fileIndllBytes)
        {
            return BitConverter.ToString(GenerateHash(fileInByte, fileIndllBytes)).Replace("-", string.Empty);
        }

        public byte[] GenerateHash(byte[] fileInByte, byte[] fileIndllBytes)
        {
            byte[] fileOutByte = new byte[fileInByte.Length + fileIndllBytes.Length];

            Buffer.BlockCopy(fileInByte, 0, fileOutByte, 0, fileInByte.Length);
            Buffer.BlockCopy(fileIndllBytes, 0, fileOutByte, fileInByte.Length, fileIndllBytes.Length);

            byte[] result = SHA1.Create().ComputeHash(fileOutByte);

            return result;
        }

        public string GenerateHashInHexStr(string path, string name)
        {
            return BitConverter.ToString(GenerateHash(path, name)).Replace("-", string.Empty);
        }

        public void CopyDLL(string generated_SHA, string build_path, string output_path, string name) //string depPath, string dllPath)
        {
            string dllDir = Path.Combine(SVXSettings.settings.dllsFolder, name + "." + generated_SHA);
            if (!Directory.Exists(dllDir))
            {
                Directory.CreateDirectory(dllDir);
            }

            try
            {
                string depPath = Path.Combine(output_path, name + ".dep");
                string dllPath = Path.Combine(output_path, name + ".dll");
                string depFile = Path.GetFileName(depPath);
                string dllFile = Path.GetFileName(dllPath);

                if (File.Exists(depPath))
                {
                    File.Copy(depPath, Path.Combine(dllDir, depFile), true);
                }
                if (File.Exists(dllPath))
                {
                    File.Copy(dllPath, Path.Combine(dllDir, dllFile), true);
                }

            }
            catch (IOException ex)
            {
                Console.WriteLine("\nMessage ---\n{0}", ex.Message);
                Console.WriteLine("\nStackTrace ---\n{0}", ex.StackTrace);
            }
        }

        public bool verifySHA1(string path, string name, string sha1)
        {
            string generatedSHA1 = GenerateHashInHexStr(path, name);

            if (generatedSHA1.Equals(sha1)) return true;

            return false;
        }
        
        public void saveToSVXFolder(string depFileName, byte[] depFileData, string dllFileName, byte[] dllFileData, string sha)
        {
            string name = Path.GetFileNameWithoutExtension(depFileName);
            string dllDir = Path.Combine(SVXSettings.settings.dllsFolder, name + "." + sha);

            if (!Directory.Exists(dllDir))
            {
                Directory.CreateDirectory(dllDir);
            }

            File.WriteAllBytes(Path.Combine(dllDir, depFileName), depFileData);
            File.WriteAllBytes(Path.Combine(dllDir, dllFileName), dllFileData);
        }
    }
}
