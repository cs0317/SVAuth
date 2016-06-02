using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using System;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace SVAuth
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // FIXME: The debugger is not breaking on uncaught exceptions like
            // it normally does by default.  For now, we have this try block.
            // You can set a breakpoint on the rethrow. ~ Matt 2016-06-01
            try
            {
                // For now, to simplify matters, the authentication agent port must
                // be specified in config.json.  The "Launch URL" in the project
                // properties should match. ~ Matt 2016-06-01
                Config.Init();

                // TODO: Implement SSL.

                var host = new WebHostBuilder()
                    .UseUrls("http://localhost:" + Config.config.AuthJSSettings.port + "/")
                    .UseKestrel()
                    .UseContentRoot(Directory.GetCurrentDirectory())
                    .UseStartup<Startup>()
                    .Build();

                host.Run();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }
    }

    // XXX This is not a very meaningful name in our context.
    public class Startup
    {

        public Startup()
        {
            Utils.InitForReal();
        }

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
            routeBuilder.MapGet("", (context) =>
            {
                context.Response.Redirect(Config.config.MainPageUrl + "?ReturnPort=" + Config.config.AuthJSSettings.port);
                return Task.CompletedTask;
            });
            ServiceProviders.Facebook.Facebook_RP.Init(routeBuilder);

            app.UseRouter(routeBuilder.Build());
        }
    }
}
