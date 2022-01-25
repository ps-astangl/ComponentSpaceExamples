using ComponentSpace.Saml2.Configuration.Serialization;
using ComponentSpace.Saml2.Metadata;
using ComponentSpace.Saml2.Metadata.Export;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Threading.Tasks;
using System.Xml;

namespace ExportMetadata
{
    /// <summary>
    /// Exports the SAML configuration as SAML metadata.
    /// 
    /// Usage: dotnet ExportMetadata.dll
    /// </summary>
    class Program
    {
        static async Task Main(string[] args)
        {
            try
            {
                var configurationParameters = GetConfigurationParameters();

                // All certificate file paths are relative to the SAML configuration file directory.
                var workingDirectory = Path.GetDirectoryName(Path.GetFullPath(configurationParameters.FileName));

                var serviceCollection = new ServiceCollection();
                var configuration = new ConfigurationBuilder().Build();

                serviceCollection.AddLogging();
                serviceCollection.AddSaml(samlConfigurations => 
                {
                    samlConfigurations.Configurations = ConfigurationDeserializer.Deserialize(configurationParameters.FileName, configurationParameters.JsonPath).Configurations;
                });

                serviceCollection.AddSingleton<IConfiguration>(configuration);

                var serviceProvider = serviceCollection.BuildServiceProvider();
                var configurationToMetadata = serviceProvider.GetService<IConfigurationToMetadata>();

                var entityDescriptor = await configurationToMetadata.ExportAsync(configurationParameters.ConfigurationName, configurationParameters.PartnerName, workingDirectory);

                SaveMetadata(entityDescriptor);
            }

            catch (Exception exception)
            {
                Console.WriteLine(exception.ToString());
            }
        }

        private static (string FileName, string JsonPath, string ConfigurationName, string PartnerName) GetConfigurationParameters()
        {
            Console.Write("SAML configuration file to export [appsettings.json]: ");

            var fileName = Console.ReadLine();

            if (string.IsNullOrEmpty(fileName))
            {
                fileName = "appsettings.json";
            }

            Console.Write("Configuration JSON path [SAML]: ");

            var jsonPath = Console.ReadLine();

            if (string.IsNullOrEmpty(jsonPath))
            {
                jsonPath = "SAML";
            }

            Console.Write("SAML configuration name [none]: ");

            var configurationName = Console.ReadLine();

            Console.Write("Partner name [none]: ");

            var partnerName = Console.ReadLine();

            return (fileName, jsonPath, configurationName, partnerName);
        }

        private static void SaveMetadata(EntityDescriptor entityDescriptor)
        {
            Console.Write("SAML metadata file [metadata.xml]: ");

            var fileName = Console.ReadLine();

            if (string.IsNullOrEmpty(fileName))
            {
                fileName = "metadata.xml";
            }

            using (XmlTextWriter xmlTextWriter = new XmlTextWriter(fileName, null))
            {
                xmlTextWriter.Formatting = Formatting.Indented;
                entityDescriptor.ToXml().OwnerDocument.Save(xmlTextWriter);
            }
        }
    }
}
