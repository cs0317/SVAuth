using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace SVAuth
{
    public static class Utils
    {
        // Currently, nothing here requires initialization. ~ t-mattmc@microsoft.com 2016-06-14

        public static JObject ReflectObject(object o)
        {
            var writer = new JTokenWriter();
            new JsonSerializer().Serialize(writer, o);
            return (JObject)writer.Token;
        }
        public static T UnreflectObject<T>(JObject jo)
        {
            return new JsonSerializer().Deserialize<T>(new JTokenReader(jo));
        }
        public static object UnreflectObject(JObject jo, Type type)
        {
            return new JsonSerializer().Deserialize(new JTokenReader(jo), type);
        }
        public static HttpContent ObjectToUrlEncodedContent(object o)
        {
            return new FormUrlEncodedContent(
                ReflectObject(o).Properties().Select(JPropertyToKvp));
        }
        // BCT WORKAROUND: lambdas ~ t-mattmc@microsoft.com 2016-06-15
        private static KeyValuePair<string, string> JPropertyToKvp(JProperty prop)
        {
            return new KeyValuePair<string, string>(prop.Name, prop.Value.ToString());
        }
        public static string ObjectToUrlEncodedString(object o)
        {
            // Should never actually block.
            return ObjectToUrlEncodedContent(o).ReadAsStringAsync().Result;
        }
        public static object ObjectFromQuery(IQueryCollection query, Type type)
        {
            return UnreflectObject(new JObject(query.Select(KvpToJProperty)), type);
        }
        public static object ObjectFromFormPost(IFormCollection form, Type type)
        {
            return UnreflectObject(new JObject(form.Select(KvpToJProperty)), type);
        }
        // BCT WORKAROUND: lambdas ~ t-mattmc@microsoft.com 2016-06-15
        private static JProperty KvpToJProperty(KeyValuePair<string, StringValues> q)
        {
            return new JProperty(q.Key, q.Value.Single());
        }

        public static string ReadStream(Stream stream)
        {
            return new StreamReader(stream).ReadToEnd();
        }
        public static string ReadContent(HttpContent content)
        {
            // Implicit wait.  Our httpClient should always read before
            // returning the response, so this should never actually wait.
            return content.ReadAsStringAsync().Result;
        }

        public static async Task AbandonAndCreateSessionAsync(GenericAuth.AuthenticationConclusion conclusion, HttpContext context)
        {
            Console.WriteLine(JsonConvert.SerializeObject(conclusion));
            //return;

            string createSessionEndpoint =
                "http://localhost/Auth.JS/platforms/" + Config.config.WebAppSettings.platform.name +
                "/CreateNewSession." + Config.config.WebAppSettings.platform.fileExtension;

            var abandonSessionRequest = new HttpRequestMessage(HttpMethod.Post, createSessionEndpoint);
            abandonSessionRequest.Headers.Add("Cookie",
                "ASP.NET_SessionId="+context.Request.Cookies["ASP.NET_SessionId"]  
                   + ";" +
                "PHPSESSID=" + context.Request.Cookies["PHPSESSID"]
                );

            HttpResponseMessage abandonSessionResponse = await SVX.Utils.PerformHttpRequestAsync(abandonSessionRequest);
            Trace.Write("Abandoned session");

            var createSessionRequest = new HttpRequestMessage(HttpMethod.Post, createSessionEndpoint);
            createSessionRequest.Headers.Add("Cookie","");
            createSessionRequest.Content = ObjectToUrlEncodedContent(conclusion);
            HttpResponseMessage createSessionResponse = await SVX.Utils.PerformHttpRequestAsync(createSessionRequest);
            Trace.Write("Created session");

            var setcookie = createSessionResponse.Headers.GetValues("Set-Cookie");
            // HTTP request and response data structures are subtly different between the HTTP client and server libraries...
            context.Response.Headers.Add("Set-Cookie", setcookie.ToArray());
            context.Response.Redirect(context.Request.Cookies["LoginPageUrl"]);
        }
    }
}
