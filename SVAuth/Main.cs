using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using System;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel;
using System.Diagnostics;

namespace SVAuth
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // For now, to simplify matters, the authentication agent port must
            // be specified in config.json.  The "Launch URL" in the project
            // properties should match. ~ t-mattmc@microsoft.com 2016-06-01
            Config.Init();
            //SVX.SVX_Ops.Init();
            SVX2.SVX_Ops.Init();

            //RunServer();
            //SVX2_Test_Concat.Test();
            //SVX2_Test_Secret.Test();
            SVX2_Test_ImplicitFlow.Test();
            SVX2_Test_AuthorizationCodeFlow.Test();

            /* When the program is run under the debugger in Visual Studio, the
             * output window closes immediately when the program exits.  Emulate
             * the behavior when the program is run without the debugger that
             * gives us a chance to read the output.  We don't need this for
             * uncaught exceptions because the debugger breaks on the exception.
             */
            if (Debugger.IsAttached)
            {
                Console.WriteLine("Press any key to continue . . . ");
                Console.ReadKey();
            }
        }

        private static void RunServer()
        {
            // BCT WORKAROUND: "new T[] { ... }" and params-style method
            // calls (which generate something similar) ~ t-mattmc@microsoft.com 2016-06-15
            var urls = new string[1];
            urls[0] = Config.config.AgentSettings.scheme + "://localhost:" + Config.config.AgentSettings.port + "/";

            var host = new WebHostBuilder()
                // The scheme specified here appears to make no difference
                // to the server, but it's displayed on the console, so
                // let's set it correctly. ~ t-mattmc@microsoft.com 2016-06-02
                .UseUrls(urls)
                .UseKestrel(ConfigureKestrel)
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseStartup<Startup>()
                .Build();

            host.Run();
        }

        // BCT WORKAROUND: lambdas ~ t-mattmc@microsoft.com 2016-06-15
        private static void ConfigureKestrel(KestrelServerOptions kestrelOptions)
        {
            switch (Config.config.AgentSettings.scheme)
            {
                case "https":
                    kestrelOptions.UseHttps(new X509Certificate2("ssl-cert/certkey.p12"));
                    break;
                case "http":
                    break;
                default:
                    throw new Exception("Unknown scheme " + Config.config.AgentSettings.scheme);
            }
        }
    }

    // XXX This is not a very meaningful name in our context.
    public class Startup
    {

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            // https://github.com/aspnet/Routing/blob/dev/samples/RoutingSample.Web/Startup.cs
            services.AddRouting();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            var routeBuilder = new RouteBuilder(app);
            routeBuilder.MapGet("", MainPageHandler);
            ServiceProviders.Facebook.Facebook_RP.Init(routeBuilder);
            ServiceProviders.Microsoft.Microsoft_RP.Init(routeBuilder);
            ServiceProviders.Google.Google_RP.Init(routeBuilder);
            ServiceProviders.Yahoo.Yahoo_RP.Init(routeBuilder);
            app.UseRouter(routeBuilder.Build());
        }

        // BCT WORKAROUND: lambdas ~ t-mattmc@microsoft.com 2016-06-15
        private static Task MainPageHandler(HttpContext context)
        {
            context.Response.Redirect(Config.config.MainPageUrl + "?ReturnPort=" + Config.config.AgentSettings.port);
            return Task.CompletedTask;
        }
    }
}
