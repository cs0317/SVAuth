using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace SVX
{
    public static class Utils
    {
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
    }

}
