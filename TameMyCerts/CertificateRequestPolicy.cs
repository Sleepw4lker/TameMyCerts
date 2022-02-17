using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace TameMyCerts
{
    public class CertificateRequestPolicy
    {
        public bool AuditOnly { get; set; }
        public string KeyAlgorithm { get; set; } = "RSA";
        public int MinimumKeyLength { get; set; }
        public int MaximumKeyLength { get; set; }
        public List<SubjectRule> Subject { get; set; }
        public List<SubjectRule> SubjectAlternativeName { get; set; }

        private static string ConvertToHumanReadableXml(string inputString)
        {
            var xmlWriterSettings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true,
                Indent = true,
                NewLineOnAttributes = true
            };

            var stringBuilder = new StringBuilder();

            var xElement = XElement.Parse(inputString);

            using (var xmlWriter = XmlWriter.Create(stringBuilder, xmlWriterSettings))
            {
                xElement.Save(xmlWriter);
            }

            return stringBuilder.ToString();
        }

        public void SaveToFile(string path)
        {
            var xmlSerializer = new XmlSerializer(typeof(CertificateRequestPolicy));

            using (var stringWriter = new StringWriter())
            {
                using (var xmlWriter = XmlWriter.Create(stringWriter))
                {
                    xmlSerializer.Serialize(xmlWriter, this);
                    var xmlData = stringWriter.ToString();

                    try
                    {
                        File.WriteAllText(path, ConvertToHumanReadableXml(xmlData));
                    }
                    catch
                    {
                        // fail silently
                    }
                }
            }
        }
    }

    public class SubjectRule
    {
        public string Field { get; set; } = string.Empty;
        public bool Mandatory { get; set; }
        public int MaxOccurrences { get; set; } = 1;
        public int MinLength { get; set; } = 1;
        public int MaxLength { get; set; } = 128;
        public List<string> AllowedPatterns { get; set; }
        public List<string> DisallowedPatterns { get; set; }
    }
}