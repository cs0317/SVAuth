using SVX;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace SVX
{
    public class VProgramGenerator
    {
        static string globalobjectText = "GlobalObjectsForSVX";
        private static XNamespace msbuild = "http://schemas.microsoft.com/developer/msbuild/2003";

        private static string vSynFile = "SynthesizedPortion.cs";

        static string nondetStr = "Nondet";
        static string porirotMainStr = "PoirotMain";
        private static int variableC = 0;
        static string tabBuffer = "          ";


        static private string syn_start = "namespace SVAuth.VProgram {\n\n" +
                                         "public class SynthesizedPortion\n" +
                                         "{\n" +
                                          "    public static void SynthesizedSequence()\n" +
                                          "    {\n";

        static private string syn_end = "    }\n}\n\n}";
        public static string Program_cs;
        public static string Assertion_cs;

        private static string GenDef(string type)
        {
            string[] typesplit = type.Split(new char[] { '.' }, StringSplitOptions.RemoveEmptyEntries);

            string typeWithoutNS = typesplit[typesplit.Length - 1];
            return type + " " + type[0] + variableC.ToString() + " = " + porirotMainStr + "." + nondetStr + "." + typeWithoutNS + "();"; 
        }

        private static string DefType(string type)
        {
            return type + " " + type[0] + variableC.ToString();
        }

        private static string generateVP(List<MethodRecord> records)
        {
            StringBuilder sb = new StringBuilder(syn_start);
            variableC = 0;

            if (records.Count > 0)
            {
                HashSet<string> definedClass = new HashSet<string>();

                variableC++;

                sb.Append(tabBuffer + GenDef(records[records.Count - 1].argType) + "\n");

                for (int i = records.Count - 1; i >= 0; i--)
                {
                    MethodRecord mr = records[i];
                    variableC++;
                    string fullClassN = mr.className;
                    string[] tClassN = fullClassN.Split(new char[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
                    string ClassN = tClassN[tClassN.Length - 1];

                    if (mr.returnType != "System.Void")
                    {
                        if (i != records.Count - 1 && mr.argType != records[i + 1].returnType)
                        {
                            sb.Append(tabBuffer + DefType(mr.argType));
                            sb.Append(" = (" + mr.argType + ")" + records[i + 1].returnType[0] + (variableC - 1).ToString() + ";\n");
                            // There can be a collision between the first letter of mr.argType and
                            // records[i + 1].returnType, so always use unique variable numbers.
                            // ~ Matt 2016-06-07
                            variableC++;
                        }

                        sb.Append(tabBuffer + DefType(mr.returnType) + " = ((" + mr.className + ")" + globalobjectText + "." + mr.rootClassName + ")." + mr.methodName + "(" + mr.argType[0] + (variableC - 1).ToString() + ");\n");
                    }
                    else
                        sb.Append(tabBuffer + "(" + globalobjectText + "." + mr.rootClassName + ")." + mr.methodName + "(" + mr.argType[0] + (variableC - 1).ToString() + ");\n");
                }
            }

            sb.Append(syn_end);

            return sb.ToString();
        }

        private static void generateVProgram(string tempVProgramPath, List<MethodRecord> methodList)
        {
            string program = generateVP(methodList);

            File.WriteAllText(Path.Combine(tempVProgramPath, "vProgram", vSynFile), program);
            File.WriteAllText(Path.Combine(tempVProgramPath, "vProgram", "Program.cs"), VProgramGenerator.Program_cs);
            File.WriteAllText(Path.Combine(tempVProgramPath, "vProgram", "Assertion.cs"), VProgramGenerator.Assertion_cs);
        }

        private static HashSet<string> getDep(HashSet<string> dllSet, string fileName)
        {
            /*
             * Add Part where 
             * !File.exists(fileName) download();
             */
            XmlReader reader = XmlReader.Create(File.OpenRead(fileName));
            HashSet<string> set_for_this_Dep = new HashSet<string>();

            while (reader.Read())
            {
                if (reader.NodeType == System.Xml.XmlNodeType.Element &&
                    reader.Name == "Reference")
                {
                    reader.Read();
                    string dllPath = reader.Value.Trim();

                    if (!dllSet.Contains(dllPath))
                    {
                        dllSet.Add(dllPath);
                        string depPath = dllPath.Substring(0, dllPath.Length-4) + ".dep";

                        set_for_this_Dep.Add(depPath);
                        //dllSet.UnionWith(getDep(dllSet, depPath));
                    }
                }
            }

            foreach (string dll in set_for_this_Dep)
            {
                dllSet.Concat(getDep(new HashSet<string>(), dll));
            }

            return dllSet;
        }

        private static void CreateTempVFolder(string tempVProgramPath)
        {
            // Note: tempVProgramPath is the equivalent of a solution.  It
            // contains project subdirectories "vProgram" and "SVAuth", because
            // .NET Core requires that DLLs be wrapped in their own project to
            // be referenced, and I had no luck with the "SVAuth" project as a
            // subdirectory of "vProgram". ~ Matt 2016-06-10

            // Copy the vProgram skeleton.
            // http://stackoverflow.com/a/58820
            // I like this because it involves the least code.
            Process copyProcess = new Process();
            copyProcess.StartInfo.UseShellExecute = false;
            copyProcess.StartInfo.FileName = @"C:\WINDOWS\system32\xcopy.exe";
            // vProgram-skeleton is relative to working directory, assumed to be SVAuth project root.
            copyProcess.StartInfo.Arguments = @"/E /I vProgram-skeleton " + tempVProgramPath;
            copyProcess.Start();
            copyProcess.WaitForExit();
            if (copyProcess.ExitCode != 0)
                throw new Exception("xcopy of vProgram skeleton failed");

#if false
            Directory.CreateDirectory(path);
            string destPath = Path.Combine(path, Path.GetFileName(SVXSettings.settings.VProgramPath));
            Directory.CreateDirectory(destPath);

            foreach (string dirPath in Directory.GetDirectories(SVXSettings.settings.VProgramPath, "*",
                SearchOption.AllDirectories))
                Directory.CreateDirectory(dirPath.Replace(SVXSettings.settings.VProgramPath, destPath));

            //Copy all the files & Replaces any files with the same name
            foreach (string newPath in Directory.GetFiles(SVXSettings.settings.VProgramPath, "*.*",
                SearchOption.AllDirectories))
                File.Copy(newPath, newPath.Replace(SVXSettings.settings.VProgramPath, destPath), true);
#endif
        }

        // This variant appears to be a little more sophisticated than the
        // original EditCSproj variant that didn't take a newVPath, which I
        // ended up using below.  Keep it here until we are sure we don't need
        // any of the code for handling multiple DLLs. ~ Matt 2016-06-10
#if false
        public static void EditCSproj(List<MethodRecord> methodList, string newVPath)
        {
            Dictionary<string, string> dllPathDict = new Dictionary<string, string>();
            HashSet<string> dllNameSet = new HashSet<string>();
            StringBuilder toAddDLL = new StringBuilder();

            /*
             * Using the method record, generate the DLL list needed to add to the project
             */
            foreach (MethodRecord mr in methodList)
            {
                string dllFolder = Path.Combine(SVXSettings.settings.dllsFolder, mr.SHA_of_DLL);

                if (Directory.Exists(dllFolder))
                {
                    string[] fileES = Directory.GetFiles(dllFolder);

                    foreach (string fileName in fileES)
                    {
                        if (fileName.EndsWith(".dll"))
                        {
                            string name = Path.GetFileNameWithoutExtension(fileName);
                            dllNameSet.Add(name);
                            dllPathDict[name] = fileName;
                        }
                        else
                        {
                            foreach (string dll_filename in getDep(new HashSet<String>(), fileName))
                            {
                                string name = Path.GetFileNameWithoutExtension(dll_filename);
                                dllNameSet.Add(name);
                                dllPathDict[name] = dll_filename;
                            }
                        }
                    }
                }
            }

            /*
             * Add the DLL list to the project
             */
            string newProjectFile = Path.Combine(newVPath, "VProgram.csproj");

            if (!File.Exists(newProjectFile)) return;

            XDocument projDefinition = XDocument.Load(newProjectFile);
            IEnumerable<XElement> referenceList = projDefinition
                .Element(msbuild + "Project")
                .Elements(msbuild + "ItemGroup")
                .Elements(msbuild + "Reference");

            XElement oneRef = null;

            for (int i = referenceList.Count() - 1; i >= 0; i--) 
            {
                XElement refEl = referenceList.ElementAt(i);
                XElement hintRef = refEl.Element(msbuild + "HintPath");
                if (hintRef != null)
                {
                    string libName = refEl.Attribute("Include").Value;
                    if (dllNameSet.Contains(libName))
                    {
                        hintRef.SetValue(dllPathDict[libName]);
                        if (!dllPathDict[libName].EndsWith("SVX_Ops.dll"))
                            toAddDLL.Append(@"bin\Debug\" + Path.GetFileName(dllPathDict[libName]) + " ");
                        dllNameSet.Remove(libName);
                        dllPathDict.Remove(libName);
                        oneRef = refEl;
                    }
                    else
                    {
                        refEl.Remove();
                    }
                }
            }

            if (oneRef != null)
            {
                foreach (string libName in dllNameSet)
                {
                    XElement newRefNode = new XElement(msbuild + "Reference",
                           new XAttribute("Include", libName),
                           new XElement(msbuild + "HintPath", dllPathDict[libName]));

                    if (!dllPathDict[libName].EndsWith("SVX_Ops.dll"))
                        toAddDLL.Append(@"bin\Debug\" + Path.GetFileName(dllPathDict[libName]) + " ");
                    oneRef.Parent.Add(newRefNode);
                }
            }
            using (StreamWriter w = File.CreateText(newProjectFile))
                projDefinition.Save(w);

            /*
             * delete bin and obj folder
             */

            string binF = Path.Combine(newVPath, "bin");
            string objF = Path.Combine(newVPath, "obj");

            Directory.Delete(binF, true);
            Directory.Delete(objF, true);
            /*
             * Add the DLL list to run.bat
             */
            string runbat = Path.Combine(newVPath, "run.bat");
            string[] runbatFileLines = File.ReadAllLines(runbat);

            for (int i = 0; i < runbatFileLines.Length; i++)
            {
                string f_n = "%file_name%.exe";
                int idx = runbatFileLines[i].IndexOf(f_n);
                if (idx != -1)
                {
                    runbatFileLines[i] = runbatFileLines[i].Substring(0, idx + f_n.Length) + " " + toAddDLL.ToString();
                }
            }
            File.WriteAllLines(runbat, runbatFileLines);
        }  
#endif
       
        private static void EditCSproj(string tempVProgramPath, List<MethodRecord> methodList)
        {
            //projectFile = Path.Combine(SVXSettings.settings.VProgramPath, "VProgram.csproj");

            // For now, the project files are hard-coded, so the only thing we
            // do here is /copy/ SVAuth.dll into the project.  (That was
            // easiest; I can write code to reference it via a relative path
            // instead if we care.)  We can clean up this code once we are more
            // sure what we want for the vProgram project setup.
            // ~ Matt 2016-06-10

            Dictionary<string, string> dllPathDict = new Dictionary<string, string>();
            HashSet<string> dllNameSet = new HashSet<string>();

            // For now, the only file we care about is SVAuth.dll.
            foreach (MethodRecord mr in methodList)
            {
                string dllFolder = Path.Combine(SVXSettings.settings.dllsFolder, mr.SHA_of_DLL);
                
                if (Directory.Exists(dllFolder))
                {
                    string[] fileES = Directory.GetFiles(dllFolder);

                    foreach (string fileName in fileES)
                    {
                        if (fileName.EndsWith(".dll"))
                        {
                            string name = Path.GetFileNameWithoutExtension(fileName);
                            if (dllNameSet.Add(name))
                            {
                                dllPathDict[name] = fileName;
                                string dest = Path.Combine(tempVProgramPath, "SVAuth", "SVAuth.dll");
                                File.Copy(fileName, dest);
                            }
                        }
                        else
                        {
                            foreach (string dep_filename in getDep(new HashSet<String>(), fileName)) {
                                string name = Path.GetFileNameWithoutExtension(dep_filename);
                                dllNameSet.Add(name);
                                dllPathDict[name] = dep_filename;
                            }
                        }
                    }
                }
            }

#if false
            // Why should this failure ever have been ignored? ~ Matt 2016-06-07
            if (!File.Exists(projectFile))
            {
                throw new Exception("vProgram project file does not exist.");
            }

            XDocument projDefinition = XDocument.Load(projectFile);
            IEnumerable<XElement> referenceList = projDefinition
                .Element(msbuild + "Project")
                .Elements(msbuild + "ItemGroup")
                .Elements(msbuild + "Reference");

            XElement oneRef = null;

            foreach (XElement refEl in referenceList) 
            {
                XElement hintRef = refEl.Element(msbuild + "HintPath");
                if (hintRef != null) 
                {
                    string libName = refEl.Attribute("Include").Value;
                    if (dllNameSet.Contains(libName))
                    {
                        hintRef.SetValue(dllPathDict[libName]);
                        dllNameSet.Remove(libName);
                        dllPathDict.Remove(libName);
                    }
                }
                oneRef = refEl;
            }
            if (oneRef != null)
            {
                foreach (string libName in dllNameSet) 
                {
                    XElement newRefNode = new XElement(msbuild + "Reference",
                           new XAttribute("Include", libName),
                           new XElement(msbuild + "HintPath", dllPathDict[libName]));

                    oneRef.Parent.Add(newRefNode);
                }
            }
            using (StreamWriter w = File.CreateText(projectFile))
                projDefinition.Save(w);
#endif
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
            Console.Write(output);  // Ideally this would be streamed. ~ Matt 2016-06-06

            if (output.IndexOf("Program has no bugs") > 0)
                return true;
            else
                return false;
        }

        public static bool generateAndVerify(List<MethodRecord> mrList)
        {
            byte[] time = BitConverter.GetBytes(DateTime.UtcNow.ToBinary());
            byte[] key = Guid.NewGuid().ToByteArray();
            // Slashes would be a problem, so use URL-safe base 64.  .NET does
            // not seem to have a built-in function for it, so just do it
            // manually. :(
            string rand_folder = Convert.ToBase64String(time.Concat(key).ToArray()).Replace('+', '-').Replace('/', '_');
            string tempVProgramPath = Path.Combine(SVXSettings.settings.VProgramPath, rand_folder);
            Console.WriteLine("Generating and verifying vProgram in: " + tempVProgramPath);

            try
            {
                Directory.CreateDirectory(SVXSettings.settings.VProgramPath);
                CreateTempVFolder(tempVProgramPath);
                EditCSproj(tempVProgramPath, mrList);
                generateVProgram(tempVProgramPath, mrList);

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

    }
}