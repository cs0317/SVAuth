using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Net.Http;

namespace SVX
{
    public static class SVX_Ops
    {
        private static ConcurrentDictionary<string, MethodRecord> methodSHADict = new ConcurrentDictionary<string, MethodRecord>();
        private static ConcurrentDictionary<string, MethodRecord> methodSHADictKEYSHA = new ConcurrentDictionary<string, MethodRecord>();
        private static ConcurrentDictionary<string, bool> SymTResultCache = new ConcurrentDictionary<string, bool>();
        private static DLLHasher dllHasher = new DLLHasher();
        private static DLLServerUploader uploader = new DLLServerUploader();
        private static DLLServerDownloader downloader = new DLLServerDownloader();
        private static string myPartyName;
        private static HashSet<string> trustedParties = new HashSet<string>();
        private static ConcurrentDictionary<string, bool> VerificationCache = new ConcurrentDictionary<string, bool>();
        private static string singleDllNameAndSha;

        public static void Init()
        {
            Utils.InitForReal();

            myPartyName = SVXSettings.settings.MyPartyName;
            trustedParties = new HashSet<string>(SVXSettings.settings.TrustedParties);

            // For now, we assume all code used by the VProgram is in the same
            // assembly as SVX, and we upload this assembly every time the
            // process starts.
            //
            // TODO: Skip the upload if the server already has the assembly
            // (needs API to query that), and re-check periodically if we add
            // cache expiration to the server.

            // Oddly named... This is the full path to the assembly file.
            string dllPath = typeof(SVX_Ops).GetTypeInfo().Module.FullyQualifiedName;
            string name = Path.GetFileNameWithoutExtension(dllPath);
            byte[] dllData = File.ReadAllBytes(dllPath);

            byte[] depData = Encoding.UTF8.GetBytes("<References>\n</References>\n");

            string sha = dllHasher.GenerateHashInHexStr(depData, dllData);
            singleDllNameAndSha = name + "." + sha;

            // Note, if the assembly was actually an EXE, this code will rename
            // it to DLL.  See if Poirot is happy with that. ~ t-mattmc@microsoft.com 2016-06-03
            if (SVXSettings.settings.CertifyLocally)
            {
                // Yes, this one wants just the sha and adds the name itself.  Go figure.
                dllHasher.saveToSVXFolder(name + ".dep", depData, name + ".dll", dllData, sha);
            }
            else
            {
                uploader.uploadDllDepData(name + ".dll", dllData, name + ".dep", depData, singleDllNameAndSha);
            }
        }

        // There is currently no good way to get the caller's MethodInfo in .NET
        // Core (https://github.com/dotnet/corefx/issues/1420), so for now, we
        // use CallerMemberName and assume it's unique.  The other option would
        // be to have the caller pass the MethodInfo, in which case we probably
        // wouldn't do any better than to look it up by name (and assume
        // uniqueness) anyway.  Eventually there may be a caller info attribute
        // that gives us the MethodInfo directly
        // (https://github.com/dotnet/roslyn/issues/351).
        // ~ t-mattmc@microsoft.com 2016-06-03

        // TODO: Consider moving recordme to a base class of the relevant
        // objects so that callers don't have to write the "this" argument
        // explicitly.  That will mean fixing GetRootClassName.
        // ~ t-mattmc@microsoft.com 2016-06-03
        public static void recordme(Object this_, SVX_MSG in_msg, SVX_MSG out_msg, bool signed, [CallerMemberName] string methodName = null)
        {
            recordCustom(this_, in_msg, out_msg, methodName, myPartyName, signed, false);
        }
        public static void recordme(Object this_, SVX_MSG in_msg, SVX_MSG out_msg, bool signed, bool server_to_server, [CallerMemberName] string methodName = null)
        {
            recordCustom(this_, in_msg, out_msg, methodName, myPartyName, signed, server_to_server);
        }
        public static void recordme(Object this_, SVX_MSG in_msg, SVX_MSG out_msg, [CallerMemberName] string methodName = null)
        {
            recordCustom(this_, in_msg, out_msg, methodName, myPartyName, false, false);
        }

        public static void recordCustom(Object o, SVX_MSG in_msg, SVX_MSG out_msg, string methodName, string partyName, bool signed, bool server_to_server)
        {
            // This will not find private methods of a superclass.  For now, we
            // require that methods be at least internal.  If we wanted to
            // support private methods, we'd have to search the base classes
            // manually.
            // http://stackoverflow.com/questions/2267277/get-private-properties-method-of-base-class-with-reflection
            // ~ t-mattmc@microsoft.com 2016-06-07
            var mi = o.GetType().GetMethod(methodName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            recordCustom(o, in_msg, out_msg, mi, partyName, signed, server_to_server);
        }

        public static void recordCustom(Object o, SVX_MSG in_msg, SVX_MSG out_msg, MethodInfo mi, string partyName, bool signed, bool server_to_server)
        {
            Type objT = o.GetType();
            var t = mi.DeclaringType;

            string rootClass = GetRootClassName(t);

            string className = objT.FullName;
            className = className.Replace("\\", string.Empty).Replace('+', '.');

            string methodName = mi.Name;

            ParameterInfo[] pi = mi.GetParameters();
            string[] args = new string[pi.Length];
            string argType = "";

            if (pi.Length > 0)
            {
                argType = pi[0].ParameterType.FullName;
                argType = argType.Replace("\\", string.Empty).Replace('+', '.');

            }

            string returnType = mi.ReturnType.FullName;

            returnType = returnType.Replace("\\", string.Empty).Replace('+', '.');

            string methodkey = returnType + " " + className + " " + rootClass + "." + methodName + "(" + argType + ")";
            string sha = "0000000000000000000000000000000000000000";

            if (!methodSHADict.ContainsKey(methodkey))
            {
                MethodRecord mr = new MethodRecord(className, rootClass, methodName, argType, returnType, singleDllNameAndSha);

                MethodHasher.saveMethod(mr);

                uploader.uploadMethodRecord(Path.Combine(SVXSettings.settings.methodsFolder, mr.getSHA() + ".txt"), mr.getSHA());

                methodSHADict.AddOrUpdate(methodkey, mr, (k, v) => v);
                methodSHADictKEYSHA.AddOrUpdate(mr.getSHA(), mr, (k, v) => v);

                sha = mr.getSHA();
            }
            else
            {
                sha = methodSHADict[methodkey].getSHA();
            }

            string colons = ":";

            if (signed)
                colons = "::";

            string in_msg_symT = in_msg.SymT;

            if (server_to_server)
            {
                int idx = in_msg_symT.IndexOf('(');

                if (idx != -1)
                    /* IIUC, this means that the last two steps of the SymT
                     * (representing the server-to-server request and response)
                     * /both/ get double parentheses, indicating that this
                     * party trusts both of them. ~ t-mattmc@microsoft.com 2016-06-07
                     */
                    in_msg_symT = '(' + in_msg_symT.Substring(0, idx) + '(' + in_msg_symT.Substring(idx, in_msg_symT.Length - idx) + "))";
            }

            out_msg.SymT = partyName + colons + sha + "(" + in_msg_symT + ")";
        }

        // I'm unsure why we are using the root class, but just port for now.
        // ~ t-mattmc@microsoft.com 2016-06-02
        public static string GetRootClassName(Type type)
        {
            while (type.GetTypeInfo().BaseType != typeof(Object))
            {
                type = type.GetTypeInfo().BaseType;
            }

            return type.Name;
        }

        public static bool Certify(SVX_MSG msg)
        {
            RemoveUntrustedSymTPart(msg);

            if (!SymTResultCache.ContainsKey(msg.SymT))
            {
                bool resultOfVerification;
                if (SVXSettings.settings.CertifyLocally)
                {
                    List<MethodRecord> mrList = MethodHasher.getDehashedRecords(methodSHADictKEYSHA, msg);

                    resultOfVerification = VProgramGenerator.generateAndVerify(mrList);
                }
                else
                {
                    resultOfVerification = uploader.verify(msg.SymT);
                }

                SymTResultCache[msg.SymT] = resultOfVerification;
            }

            return SymTResultCache[msg.SymT];
        }

        private static void RemoveUntrustedSymTPart(SVX_MSG msg)
        {
            string peeledSymT = msg.SymT;
            int pos = 0, st_of_sym = 0, brk_cnt = 0;
            bool signed_symT = true;

            for (; pos < msg.SymT.Length && msg.SymT[pos] != ')'; pos++)
            {
                if (msg.SymT[pos] == ':')
                {
                    if (msg.SymT[pos + 1] == ':' || signed_symT)
                    {
                        string partyN = msg.SymT.Substring(st_of_sym, pos - st_of_sym);

                        if (!trustedParties.Contains(partyN))
                        {
                            peeledSymT = peeledSymT.Substring(0, st_of_sym) + new String(')', brk_cnt);
                            break;
                        }

                        if (msg.SymT[pos + 1] == ':')
                            pos++;
                    }
                    else
                    {
                        peeledSymT = peeledSymT.Substring(0, st_of_sym) + new String(')', brk_cnt);
                        break;
                    }
                }
                if (msg.SymT[pos] == '(')
                {
                    brk_cnt++;
                    if (msg.SymT[pos + 1] == '(')
                    {
                        signed_symT = true;
                        pos++;
                        brk_cnt++;
                    }
                    else
                        signed_symT = false;

                    st_of_sym = pos + 1;
                }
            }

            msg.SymT = peeledSymT;
        }

#if false
        static string dehash_server_host = "http://protoagnostic.cloudapp.net:8500/";
        static string upload_path = "Hash/CodeToHash";
//        static string dehash_path = "Hash/HashToCode";
        static Dictionary<string, string> codeHashMap = new Dictionary<string, string>();
#endif

        //a.com:CALL1    -- colon controlled by bSelfSuppliedInput
        static public string ConstructSymT(string methodCall, bool bSigned)
        {
            return String.Format("{0}{1}{2}", myPartyName, bSigned ? "::" : ":", methodCall);
        }

        //hash1(Sym_T1)    -- parentheses controlled by bSelfSuppliedInput
        static public string ConstructSimpleCall(string srcHash, string SymT_in, bool bSelfSuppliedInput)
        {
            return String.Format("{0}{1}{2}{3}", srcHash,
                                bSelfSuppliedInput ? "((" : "(",
                                SymT_in,
                                bSelfSuppliedInput ? "))" : ")");
        }

        //input = a.com:hash1(...) and hash2
        //output= hash2((a.com:hash1((...))))
        static public string ConstructServerServerCall(string SymT_ServerServerCall, string srcHash_postCall)
        {
            SymT_ServerServerCall = ChangeToDoubleParentheses(SymT_ServerServerCall);
            return String.Format("{0}(({1}))", srcHash_postCall, SymT_ServerServerCall);
        }

        static string ChangeToDoubleParentheses(string SymT_ServerServerCall)
        {
            int pos = SymT_ServerServerCall.IndexOf(myPartyName);
            if (pos < 2) return SymT_ServerServerCall;
            if (SymT_ServerServerCall[pos - 1] == '(' && SymT_ServerServerCall[pos - 2] != '(')
                return String.Format("{0}({1})", SymT_ServerServerCall.Substring(0, pos - 1), SymT_ServerServerCall.Substring(pos - 1));
            else
                return SymT_ServerServerCall;
        }

        //this function converts a piece of code to a hash
        // Looks unused ~ t-mattmc@microsoft.com 2016-06-03
#if false
        public static string code_to_hash(string code)
        {

            foreach (KeyValuePair<string, string> entry in codeHashMap)
            {
                if (entry.Value == code)
                {
                    return entry.Key;
                }
            }

            //resp is in the format of OK|HASH or Error: ERROR MESSAGE
            string resp = httpClient.PostAsync(dehash_server_host + upload_path, new StringContent(code))
                .Result.Content.ReadAsStringAsync().Result;
            string hash = "";

            if (resp.IndexOf("Error") != -1)
            {
                Console.WriteLine(resp);
            }
            else
            {
                string[] split = resp.Split(new char[] { '|' });
                hash = split[1];
            }

            return hash;
        }
#endif

    }
}