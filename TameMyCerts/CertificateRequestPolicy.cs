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
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace TameMyCerts
{
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

    public class DirectoryServicesMapping
    {
        public string SearchRoot { get; set; }
        public string CertificateAttribute { get; set; } = "userPrincipalName";
        public string DirectoryServicesAttribute { get; set; } = "userPrincipalName";
        public string ObjectCategory { get; set; } = "user";
        public List<string> AllowedSecurityGroups { get; set; } = new List<string>();
        public List<string> DisallowedSecurityGroups { get; set; } = new List<string>();

        public List<RelativeDistinguishedName> SubjectDistinguishedName { get; set; } =
            new List<RelativeDistinguishedName>();
    }

    public class RelativeDistinguishedName
    {
        public string Field { get; set; } = string.Empty;
        public string DirectoryServicesAttribute { get; set; } = "userPrincipalName";
        public bool Mandatory { get; set; }
    }

    public class SubjectRule
    {
        public string Field { get; set; } = string.Empty;
        public bool Mandatory { get; set; }
        public int MaxOccurrences { get; set; } = 1;
        public int MinLength { get; set; } = 1;
        public int MaxLength { get; set; } = 128;
        public List<Pattern> Patterns { get; set; } = new List<Pattern>();
    }

    public class Pattern
    {
        public string Expression { get; set; }
        public string TreatAs { get; set; } = "RegEx";
        public string Action { get; set; } = "Allow";

        public bool IsMatch(string term, bool matchOnError = false)
        {
            try
            {
                switch (TreatAs.ToLowerInvariant())
                {
                    case "regex": return new Regex(@"" + Expression + "").IsMatch(term);
                    case "cidr": return IPAddress.Parse(term).IsInRange(Expression);
                    default: return false;
                }
            }
            catch
            {
                return matchOnError;
            }
        }
    }
}