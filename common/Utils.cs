using Microsoft.AspNetCore.Http;
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
                ReflectObject(o).Properties()
                .Select((prop) => new KeyValuePair<string, string>(prop.Name, prop.Value.ToString())));
        }
        public static string ObjectToUrlEncodedString(object o)
        {
            // Should never actually block.
            return ObjectToUrlEncodedContent(o).ReadAsStringAsync().Result;
        }
        public static T ObjectFromForm<T>(string formText)
        {
            return UnreflectObject<T>(null);
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

        // XXX Better place to put it?
        // XXX Where to dispose?
        static HttpClient httpClient;

        // Should only be called by Startup.
        public static void InitForReal()
        {
            httpClient = new HttpClient();
        }

        public static async Task<HttpResponseMessage> PerformHttpRequestAsync(HttpRequestMessage req)
        {
            HttpResponseMessage resp = await httpClient.SendAsync(req);
            resp.EnsureSuccessStatusCode();
            return resp;
        }

        public static async Task AbandonAndCreateSessionAsync(GenericAuth.AuthenticationConclusion conclusion, HttpContext context)
        {
            Console.WriteLine(JsonConvert.SerializeObject(conclusion));
            //return;

            string createSessionEndpoint =
                "http://localhost/Auth.JS/platforms/" + Config.config.WebAppSettings.platform.name +
                "/CreateNewSession." + Config.config.WebAppSettings.platform.fileExtension;

            var abandonSessionRequest = new HttpRequestMessage(HttpMethod.Post, createSessionEndpoint);
            await PerformHttpRequestAsync(abandonSessionRequest);
            Trace.Write("Abandoned session");

            var createSessionRequest = new HttpRequestMessage(HttpMethod.Post, createSessionEndpoint);
            createSessionRequest.Content = ObjectToUrlEncodedContent(conclusion);
            HttpResponseMessage createSessionResponse = await PerformHttpRequestAsync(createSessionRequest);
            Trace.Write("Created session");

            var setcookie = createSessionResponse.Headers.GetValues("Set-Cookie");
            // HTTP request and response data structures are subtly different between the HTTP client and server libraries...
            context.Response.Headers.Add("Set-Cookie", setcookie.ToArray());
            context.Response.Redirect(context.Request.Cookies["LoginPageUrl"]);
        }
    }
}
