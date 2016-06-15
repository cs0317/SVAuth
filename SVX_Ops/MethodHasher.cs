using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SVX
{
    public class MethodRecord : IEquatable<MethodRecord>
    {
        public string className
        {
            get;
            set;
        }
        public string methodName
        {
            get;
            set;
        }
        public string argType
        {
            get;
            set;
        }
        public string returnType
        {
            get;
            set;
        }

        public string SHA_of_DLL
        {
            get;
            set;
        }

        public string rootClassName
        {
            get;
            set;
        }
        
        private string SHA_of_record;
        private SHA1 sha = SHA1.Create();

        public MethodRecord(string className, string rootClassName, string methodName, string argType, string returnType, string SHA_of_DLL)
        {
            this.className = className;
            this.methodName = methodName;
            this.argType = argType;
            this.returnType = returnType;
            this.SHA_of_DLL = SHA_of_DLL;
            this.rootClassName = rootClassName;
        }

        public override int GetHashCode()
        {
            return Convert.ToInt32(SHA_of_DLL);
        }

        public MethodRecord()
        { }

        public string getSHA()
        {
            if (SHA_of_record != null) return SHA_of_record;

            StringBuilder sb = new StringBuilder();

            sb.Append(SHA_of_DLL + "\n");
            sb.Append(returnType + " " + className + " " + rootClassName + " " + methodName + "(");

            sb.Append(argType + "");

            sb.Append(")\n");

            byte[] recordBytes = new byte[sb.Length * sizeof(char)];

            System.Buffer.BlockCopy(sb.ToString().ToCharArray(), 0, recordBytes, 0, recordBytes.Length);

            byte[] result = sha.ComputeHash(recordBytes);

            SHA_of_record = BitConverter.ToString(result).Replace("-", string.Empty);

            SHA_of_record = className + "." + methodName + "." + SHA_of_record; 

            return SHA_of_record;
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();

            sb.Append(SHA_of_record + "\n");
            sb.Append(SHA_of_DLL + "\n");
            sb.Append(returnType + " " + className + " " + rootClassName + " " + methodName + "(");

            sb.Append(argType + "");

            sb.Append(")\n");

            return sb.ToString();
        }

        public string getMethod()
        {
            StringBuilder sb = new StringBuilder();

            sb.Append(returnType + " " + className + " " + methodName + "(");

            sb.Append(argType + "");

            sb.Append(")\n");
            return sb.ToString();
        }

        public override bool Equals(object obj)
        {
            if (obj == null) return false;
            MethodRecord mr = obj as MethodRecord;

            if (mr == null) return false;

            return Equals(mr);
        }

        public bool Equals(MethodRecord mr)
        {
            if (mr == null) return false;

            return (SHA_of_record == mr.getSHA());
        }
    }

    public class MethodHasher
    {
        public static void saveMethod(MethodRecord mr)
        {
            if (!Directory.Exists(SVXSettings.settings.methodsFolder))
            {
                Directory.CreateDirectory(SVXSettings.settings.methodsFolder);
            }

            File.WriteAllText(Path.Combine(SVXSettings.settings.methodsFolder, mr.getSHA() + ".txt"), mr.ToString());
        }

        public static string CalculateSHAFromMRText(string text)
        {
            string forSHA = text.Substring(text.IndexOf('\n') + 1);

            byte[] recordBytes = new byte[forSHA.Length * sizeof(char)];

            System.Buffer.BlockCopy(forSHA.ToCharArray(), 0, recordBytes, 0, recordBytes.Length);

            SHA1 sha = SHA1.Create();
            byte[] result = sha.ComputeHash(recordBytes);

            string SHA = BitConverter.ToString(result).Replace("-", string.Empty);


            return SHA;
        }

        public static MethodRecord getMRFromFile(string mr_sha)
        {
            string methodFile = Path.Combine(SVXSettings.settings.methodsFolder, mr_sha + ".txt");
            if (!File.Exists(methodFile))
                DLLServerDownloader.downloadMethodRecord(mr_sha);

            string[] lines = System.IO.File.ReadAllLines(methodFile);
            string shaR = lines[0];
            string shaD = lines[1];

            string m = lines[2]; 

            string[] method = m.Split(new char[] { ' ', ')', '('});            

            string returnN = method[0];
            string classN = method[1];
            string rootClassN = method[2];
            string methodN = method[3];
            string param = method[4];

            MethodRecord mr = new MethodRecord(classN, rootClassN, methodN, param, returnN, shaD);

            return mr;
        }

        public static List<MethodRecord> getDehashedRecords(ConcurrentDictionary<string, MethodRecord> methodSHADictKEYSHA, SVX_MSG msg)
        {
            List<MethodRecord> mrList = new List<MethodRecord>();
            string[] sha_methods = msg.SymT.Split(new char[] { ' ', '(', ')' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string method in sha_methods)
            {
                string[] partyNameSplit = method.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);

                if (partyNameSplit.Length <= 1) continue;

                string stripped_method = partyNameSplit[1];

                MethodRecord mr = null;
                if (!methodSHADictKEYSHA.ContainsKey(stripped_method))
                {
                    if (!File.Exists(Path.Combine(SVXSettings.settings.methodsFolder, stripped_method + ".txt")))
                    {
                        DLLServerDownloader.downloadMethodRecord(stripped_method);
                    }
                    mr = MethodHasher.getMRFromFile(stripped_method);
                }
                else
                {
                    mr = methodSHADictKEYSHA[stripped_method];
                }
                if (!Directory.Exists(Path.Combine(SVXSettings.settings.dllsFolder, mr.SHA_of_DLL)))
                {
                    DLLServerDownloader.downloadDLLandDep(mr.SHA_of_DLL);
                }

                mrList.Add(mr);
            }

            return mrList;
        }

        public static List<MethodRecord> getDehashedRecords(string SymT)
        {
            List<MethodRecord> mrList = new List<MethodRecord>();
            string[] sha_methods = SymT.Split(new char[] { ' ', '(', ')' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string method in sha_methods)
            {
                string[] partyNameSplit = method.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);

                if (partyNameSplit.Length <= 1) continue;

                string stripped_method = partyNameSplit[1];

                MethodRecord mr = MethodHasher.getMRFromFile(stripped_method);

                mrList.Add(mr);
            }

            return mrList;

        }

    }
}
