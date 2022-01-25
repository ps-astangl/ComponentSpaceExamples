using ComponentSpace.Saml2;
using ComponentSpace.Saml2.Assertions;
using ComponentSpace.Saml2.XmlSecurity.Encryption;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Decrypt
{
    /// <summary>
    /// Decrypts SAML v2.0 assertions, attributes and IDs.
    /// 
    /// Usage: dotnet Decrypt.dll <fileName> -c <certificateFileName> -p <password> [-o <outputFileName>]
    /// 
    /// where the file contains an encrypted SAML assertion, attribute or ID.
    /// 
    /// SAML assertions, attributes and IDs are decrypted using the private key associated with the X.509 certificate.
    /// </summary>
    class Program
    {
        static class ElementNames
        {
            public const string EncryptedAssertion = "EncryptedAssertion";
            public const string EncryptedAttribute = "EncryptedAttribute";
            public const string EncryptedID = "EncryptedID";
            public const string NewEncryptedID = "NewEncryptedID";
        }

        static void Main(string[] args)
        {
            try
            {
                var commandLineApplication = new CommandLineApplication()
                {
                    Name = "Decrypt",
                    Description = "Decrypts an encrypted SAML assertion, attribute or ID"
                };

                commandLineApplication.HelpOption("-? | -h | --help");

                var fileNameArgument = commandLineApplication.Argument(
                    "fileName",
                    "The XML file containing an encrypted SAML assertion, attribute or ID");

                var certificateOption = commandLineApplication.Option(
                    "-c | --certificate <certificateFileName>",
                    "The certificate file used to decrypt the assertion, attribute or ID",
                    CommandOptionType.SingleValue);

                var passwordOption = commandLineApplication.Option(
                    "-p | --password <password>",
                    "The certificate file password",
                    CommandOptionType.SingleValue);

                var outputOption = commandLineApplication.Option(
                    "-o | --output <outputFileName>",
                    "The generated XML file containing the decrypted assertion, attribute or ID",
                    CommandOptionType.SingleValue);

                commandLineApplication.OnExecute(() =>
                {
                    if (string.IsNullOrEmpty(fileNameArgument.Value))
                    {
                        Console.WriteLine("The file name is missing.");
                        commandLineApplication.ShowHelp();

                        return -1;
                    }

                    if (string.IsNullOrEmpty(certificateOption.Value()))
                    {
                        Console.WriteLine("The certificate file name is missing.");
                        commandLineApplication.ShowHelp();

                        return -1;
                    }

                    if (string.IsNullOrEmpty(passwordOption.Value()))
                    {
                        Console.WriteLine("The certificate file password is missing.");
                        commandLineApplication.ShowHelp();

                        return -1;
                    }

                    Decrypt(fileNameArgument.Value, certificateOption.Value(), passwordOption.Value(), outputOption.Value());

                    return 0;
                });

                commandLineApplication.Execute(args);
            }

            catch (Exception exception)
            {
                Console.WriteLine(exception.ToString());
            }
        }

        private static void Decrypt(string fileName, string certificateFileName, string certificatePassword, string outputFileName)
        {
            if (!File.Exists(fileName))
            {
                throw new ArgumentException($"The file {fileName} doesn't exist.");
            }

            var xmlDocument = new XmlDocument
            {
                PreserveWhitespace = true
            };

            xmlDocument.Load(fileName);

            if (!File.Exists(certificateFileName))
            {
                throw new ArgumentException($"The certificate file {certificateFileName} doesn't exist.");
            }

            var serviceCollection = new ServiceCollection();

            serviceCollection.AddLogging();
            serviceCollection.AddSaml();

            var serviceProvider = serviceCollection.BuildServiceProvider();
            var xmlEncryption = serviceProvider.GetService<IXmlEncryption>();

            if (xmlDocument.DocumentElement.NamespaceURI != SamlConstants.NamespaceUris.Assertion)
            {
                throw new ArgumentException($"Unexpected namespace URI: {xmlDocument.DocumentElement.NamespaceURI}");
            }

            EncryptedElementType encryptedElement;

            switch (xmlDocument.DocumentElement.LocalName)
            {
                case ElementNames.EncryptedAssertion:
                    encryptedElement = new EncryptedAssertion(xmlDocument.DocumentElement);
                    break;

                case ElementNames.EncryptedAttribute:
                    encryptedElement = new EncryptedAttribute(xmlDocument.DocumentElement);
                    break;

                case ElementNames.EncryptedID:
                    encryptedElement = new EncryptedID(xmlDocument.DocumentElement);
                    break;

                case ElementNames.NewEncryptedID:
                    encryptedElement = new NewEncryptedID(xmlDocument.DocumentElement);
                    break;

                default:
                    throw new ArgumentException($"Unexpected element name: {xmlDocument.DocumentElement.LocalName}");
            }

            XmlElement plainTextElement = null;

            using (var x509Certificate = new X509Certificate2(certificateFileName, certificatePassword))
            {
                using (var privateKey = x509Certificate.GetRSAPrivateKey())
                {
                    plainTextElement = xmlEncryption.Decrypt(
                        encryptedElement.EncryptedData,
                        encryptedElement.EncryptedKeys,
                        privateKey);
                }
            }

            if (string.IsNullOrEmpty(outputFileName))
            {
                outputFileName = fileName;
            }

            plainTextElement.OwnerDocument.Save(outputFileName);
        }
    }
}
