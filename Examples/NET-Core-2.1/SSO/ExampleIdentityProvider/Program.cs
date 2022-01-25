using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

namespace ExampleIdentityProvider
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .ConfigureLogging(configureLogging => configureLogging.ClearProviders())
                .UseSerilog((webHostBuilderContext, loggerConfiguration) => loggerConfiguration.ReadFrom.Configuration(webHostBuilderContext.Configuration))
                .UseStartup<Startup>();
    }
}
