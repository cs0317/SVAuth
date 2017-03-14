﻿using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SVAuth
{
    public static class Utils
    {
        // The httpClient is going to live here until we have a client library
        // for the certification server again.
        // ~ t-mattmc@microsoft.com 2016-07-22
        public static void InitForReal()
        {
            httpClient = new HttpClient(new HttpClientHandler { UseCookies = false });
        }

        // XXX Better place to put it?
        // XXX Where to dispose?
        static HttpClient httpClient;

        public static async Task<HttpResponseMessage> PerformHttpRequestAsync(HttpRequestMessage req)
        {
            HttpResponseMessage resp = await httpClient.SendAsync(req);
            resp.EnsureSuccessStatusCode();
            return resp;
        }

        // Serialization stuff.

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
        public static object ObjectFromQueryString(string queryString, Type type)
        {
            // http://stackoverflow.com/a/29993210
            return UnreflectObject(new JObject(QueryHelpers.ParseQuery(queryString).Select(KvpToJProperty)), type);
        }
        public static JObject JObjectFromQueryString(string queryString)
        {
            return new JObject(QueryHelpers.ParseQuery(queryString).Select(KvpToJProperty));
        }
        public static object ObjectFromFormPost(IFormCollection form, Type type)
        {
            return UnreflectObject(new JObject(form.Select(KvpToJProperty)), type);
        }
        // BCT WORKAROUND: lambdas ~ t-mattmc@microsoft.com 2016-06-15
        private static JProperty KvpToJProperty<T>(KeyValuePair<string, T> q)
            where T : IEnumerable<string>  // because KeyValuePair is not covariant
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

        public static string Digest(string input) =>
            // Go between string and byte[], increasing the length both ways!
            SVX.Utils.ToUrlSafeBase64String(
                SHA256.Create()
                .ComputeHash(Encoding.UTF8.GetBytes(input)));

        public static string Hmac(string input, string key) =>
            SVX.Utils.ToUrlSafeBase64String(
                new HMACSHA256(Encoding.UTF8.GetBytes(key))
                .ComputeHash(Encoding.UTF8.GetBytes(input)));

        // Session management

        public static async Task AbandonAndCreateSessionAsync(GenericAuth.AuthenticationConclusion conclusion, SVAuthRequestContext context)
        {
            Console.WriteLine(JsonConvert.SerializeObject(conclusion.userProfile));
            //return;

            string createSessionEndpoint =
                Config.config.internalPlatformRootUrl +
                "CreateNewSession." + Config.config.WebAppSettings.platform.fileExtension;

            var abandonSessionRequest = new HttpRequestMessage(HttpMethod.Post, createSessionEndpoint);
            abandonSessionRequest.Headers.Add("Cookie",
                "ASP.NET_SessionId="+context.http.Request.Cookies["ASP.NET_SessionId"]  
                   + ";" +
                "PHPSESSID=" + context.http.Request.Cookies["PHPSESSID"]
                );

            HttpResponseMessage abandonSessionResponse = await PerformHttpRequestAsync(abandonSessionRequest);
            Trace.Write("Abandoned session");

            var createSessionRequest = new HttpRequestMessage(HttpMethod.Post, createSessionEndpoint);
            createSessionRequest.Headers.Add("Cookie","");
            createSessionRequest.Content = ObjectToUrlEncodedContent(conclusion.userProfile);
            HttpResponseMessage createSessionResponse = await PerformHttpRequestAsync(createSessionRequest);
            Trace.Write("Created session");

            var setcookie = createSessionResponse.Headers.GetValues("Set-Cookie");
            // HTTP request and response data structures are subtly different between the HTTP client and server libraries...
            // What we really want is "add another Set-Cookie value, creating
            // the header if it doesn't exist yet".  For now, just try to create
            // the header, and we'll get an exception if there was already one
            // (e.g., for the SVAuthSessionID, which shouldn't normally be set
            // in the same response).
            context.http.Response.Headers.Add("Set-Cookie", setcookie.ToArray());

            string redir_url = context.http.Request.Cookies["LoginPageUrl"];
            Console.WriteLine("LoginPageUrl="+ redir_url);
            if (redir_url == null || redir_url == "")
            {
                Microsoft.Extensions.Primitives.StringValues referer;
                context.http.Request.Headers.TryGetValue("referer", out referer);
                redir_url = System.Net.WebUtility.UrlDecode(referer);
                Console.WriteLine("referer=" + redir_url);
            }
            context.http.Response.StatusCode = 303;
            context.http.Response.Redirect(redir_url);
        }
    }

    public class SVAuthRequestContext
    {
        // Shorter name than style guidelines would normally dictate,
        // because we'll use it so much.
        public readonly HttpContext http;

        // Currently, we always use cookies.  The first time we write a real
        // implementation of the server side of a server-to-server call, we'll
        // need an option to disable cookies and just generate a random facet
        // every time.
        public readonly SVX.Channel client;

        const string cookieName = "SVAuthSessionID";

        // This will automatically set an agent cookie if the client did not
        // pass one.  Call it only once on a given HttpContext, because it
        // isn't smart enough to check if there's already a Set-Cookie.
        public SVAuthRequestContext(SVX.Entity serverPrincipal, HttpContext httpContext)
        {
            http = httpContext;
            string sessionId;
            if (!httpContext.Request.Cookies.TryGetValue(cookieName, out sessionId))
            {
                sessionId = SVX.Utils.RandomIdString();
                httpContext.Response.Headers.Add("Set-Cookie", $"{cookieName}={sessionId}; path=/");
            }
            // Arguably it would be better design to start with the public
            // session ID and compute the session cookie as an HMAC, but
            // this is a little easier.
            string publicSessionId = Utils.Digest(sessionId);
            client = SVX.Channel.Of(serverPrincipal, publicSessionId);
        }
    }
}
