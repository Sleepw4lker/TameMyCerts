// Copyright 2021-2024 Uwe Gradenegger <uwe@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace TameMyCerts.Models;

// Must be public due to XML serialization, otherwise 0x80131509 / System.InvalidOperationException
[XmlRoot(ElementName = "CertificateRequestPolicy")]
public class CertificateRequestPolicy
{
    [XmlElement(ElementName = "AuditOnly")]
    public bool AuditOnly { get; set; }

    [XmlElement(ElementName = "NotAfter")] 
    public string NotAfter { get; set; } = string.Empty;

    [XmlArray(ElementName = "AllowedProcesses")]
    [XmlArrayItem(ElementName = "string")]
    public List<string> AllowedProcesses { get; set; } = new();

    [XmlArray(ElementName = "DisallowedProcesses")]
    [XmlArrayItem(ElementName = "string")]
    public List<string> DisallowedProcesses { get; set; } = new();

    [XmlArray(ElementName = "AllowedCryptoProviders")]
    [XmlArrayItem(ElementName = "string")]
    public List<string> AllowedCryptoProviders { get; set; } = new();

    [XmlArray(ElementName = "DisallowedCryptoProviders")]
    [XmlArrayItem(ElementName = "string")]
    public List<string> DisallowedCryptoProviders { get; set; } = new();

    [XmlArray(ElementName = "CrlDistributionPoints")]
    [XmlArrayItem(ElementName = "string")]
    public List<string> CrlDistributionPoints { get; set; } = new();

    [XmlArray(ElementName = "AuthorityInformationAccess")]
    [XmlArrayItem(ElementName = "string")]
    public List<string> AuthorityInformationAccess { get; set; } = new();

    [XmlArray(ElementName = "OnlineCertificateStatusProtocol")]
    [XmlArrayItem(ElementName = "string")]
    public List<string> OnlineCertificateStatusProtocol { get; set; } = new();

    [XmlElement(ElementName = "MinimumKeyLength")]
    public int MinimumKeyLength { get; set; }

    [XmlElement(ElementName = "MaximumKeyLength")]
    public int MaximumKeyLength { get; set; }

    [XmlArray(ElementName = "Subject")] 
    public List<SubjectRule> Subject { get; set; } = new();

    [XmlArray(ElementName = "SubjectAlternativeName")]
    public List<SubjectRule> SubjectAlternativeName { get; set; } = new();

    [XmlArray(ElementName = "OutboundSubject")]
    public List<OutboundSubjectRule> OutboundSubject { get; set; } = new();

    [XmlArray(ElementName = "OutboundSubjectAlternativeName")]
    public List<OutboundSubjectRule> OutboundSubjectAlternativeName { get; set; } = new();

    [XmlElement(ElementName = "SecurityIdentifierExtension")]
    public string SecurityIdentifierExtension { get; set; } = "Deny";

    [XmlElement(ElementName = "DirectoryServicesMapping")]
    public DirectoryServicesMapping DirectoryServicesMapping { get; set; }

    [XmlArray(ElementName = "YubiKeyPolicies")]
    [XmlArrayItem(ElementName = "YubiKeyPolicy")]
    public List<YubikeyPolicy> YubikeyPolicy { get; set; } = new();

    [XmlElement(ElementName = "SupplementDnsNames")]
    public bool SupplementDnsNames { get; set; }

    [XmlElement(ElementName = "SupplementUnqualifiedNames")]
    public bool SupplementUnqualifiedNames { get; set; } = true;

    [XmlElement(ElementName = "ReadSubjectFromRequest")]
    public bool ReadSubjectFromRequest { get; set; }

    [XmlElement(ElementName = "PermitEmptyIdentities")]
    public bool PermitEmptyIdentities { get; set; }

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

                File.WriteAllText(path, ConvertToHumanReadableXml(xmlData));
            }
        }
    }

    public static CertificateRequestPolicy LoadFromFile(string path)
    {
        var xmlSerializer = new XmlSerializer(typeof(CertificateRequestPolicy));
        xmlSerializer.UnknownElement += new XmlElementEventHandler(UnknownElementHandler);
        xmlSerializer.UnknownAttribute += new XmlAttributeEventHandler(UnknownAttributeHandler);

        using (var reader = new StreamReader(path))
        {
            return (CertificateRequestPolicy)xmlSerializer.Deserialize(reader.BaseStream);
        }
    }
    public string SaveToString()
    {
        var xmlSerializer = new XmlSerializer(typeof(CertificateRequestPolicy));

        using (var stringWriter = new StringWriter())
        {
            using (var xmlWriter = XmlWriter.Create(stringWriter))
            {
                xmlSerializer.Serialize(xmlWriter, this);
                var xmlData = stringWriter.ToString();

                return ConvertToHumanReadableXml(xmlData);
            }
        }
    }
    private static void UnknownElementHandler(object sender, XmlElementEventArgs e)
    {
         ETWLogger.Log.TMC_92_Policy_Unknown_XML_Element(e.Element.Name, e.LineNumber, e.LinePosition);
    }

    // Event handler for unknown attributes
    private static void UnknownAttributeHandler(object sender, XmlAttributeEventArgs e)
    {
        ETWLogger.Log.TMC_93_Policy_Unknown_XML_Attribute(e.Attr.Name, e.Attr.Value, e.LineNumber, e.LinePosition);
    }

}