using ComponentSpace.Saml2.Configuration;
using ComponentSpace.Saml2.Configuration.Serialization;
using ComponentSpace.Saml2.Metadata.Import;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Threading.Tasks;

namespace ImportMetadata
{
    /// <summary>
    /// Imports SAML metadata into the SAML configuration.
    /// 
    /// Usage: dotnet ImportMetadata.dll
    /// </summary>
    class Program
    {
        static async Task Main()
        {
            try
            {
                Console.Write("SAML metadata file or URL to import: ");
                var metadataLocation = Console.ReadLine();

                var serviceCollection = new ServiceCollection();

                serviceCollection.AddLogging();
                serviceCollection.AddSaml();

                var serviceProvider = serviceCollection.BuildServiceProvider();
                var metadataToConfiguration = serviceProvider.GetService<IMetadataToConfiguration>();

                var samlConfigurations = await (metadataLocation.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? metadataToConfiguration.ImportUrlAsync(metadataLocation)
                    : metadataToConfiguration.ImportFileAsync(metadataLocation));

                SaveConfiguration(samlConfigurations);
            }

            catch (Exception exception)
            {
                Console.WriteLine(exception.ToString());
            }
        }

        private static void SaveConfiguration(SamlConfigurations samlConfigurations)
        {
            Console.Write("SAML configuration file [saml.json]: ");

            var fileName = Console.ReadLine();

            if (string.IsNullOrEmpty(fileName))
            {
                fileName = "saml.json";
            }

            File.WriteAllText(fileName, ConfigurationSerializer.Serialize(samlConfigurations));
        }
    }
}
