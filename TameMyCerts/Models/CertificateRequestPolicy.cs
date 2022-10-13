// Copyright 2021 Uwe Gradenegger <uwe@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace TameMyCerts.Models
{
    // Must be public due to XML serialization, otherwise 0x80131509 / System.InvalidOperationException
    public class CertificateRequestPolicy
    {
        public bool AuditOnly { get; set; }
        public string NotAfter { get; set; } = string.Empty;
        public List<string> AllowedProcesses { get; set; } = new List<string>();
        public List<string> DisallowedProcesses { get; set; } = new List<string>();
        public List<string> AllowedCryptoProviders { get; set; } = new List<string>();
        public List<string> DisallowedCryptoProviders { get; set; } = new List<string>();
        public string KeyAlgorithm { get; set; } = "RSA";
        public int MinimumKeyLength { get; set; }
        public int MaximumKeyLength { get; set; }
        public List<SubjectRule> Subject { get; set; } = new List<SubjectRule>();
        public List<SubjectRule> SubjectAlternativeName { get; set; } = new List<SubjectRule>();
        public string SecurityIdentifierExtension { get; set; } = "Deny";
        public DirectoryServicesMapping DirectoryServicesMapping { get; set; }
        public bool SupplementDnsNames { get; set; }

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

        public static CertificateRequestPolicy LoadFromFile(string path)
        {
            var xmlSerializer = new XmlSerializer(typeof(CertificateRequestPolicy));

            try
            {
                using (var reader = new StreamReader(path))
                {
                    return (CertificateRequestPolicy) xmlSerializer.Deserialize(reader.BaseStream);
                }
            }
            catch
            {
                return null;
            }
        }
    }
}