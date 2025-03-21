// Copyright 2021-2025 Uwe Gradenegger <info@gradenegger.eu>
// Copyright 2024 Oscar Virot <virot@virot.com>

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
using TameMyCerts.Enums;

namespace TameMyCerts.Models;

// Must be public due to XML serialization, otherwise 0x80131509 / System.InvalidOperationException
[XmlRoot(ElementName = "YubiKeyPolicy")]
public class YubikeyPolicy
{
    [XmlElement(ElementName = "Action")]
    public YubikeyPolicyAction Action { get; set; } = YubikeyPolicyAction.Allow;

    [XmlArray(ElementName = "PinPolicy")]
    [XmlArrayItem(ElementName = "string")]
    public List<YubikeyPinPolicy> PinPolicies { get; set; } = new();

    [XmlArray(ElementName = "TouchPolicy")]
    [XmlArrayItem(ElementName = "string")]
    public List<YubikeyTouchPolicy> TouchPolicies { get; set; } = new();

    [XmlArray(ElementName = "FormFactor")]
    [XmlArrayItem(ElementName = "string")]
    public List<YubikeyFormFactor> Formfactor { get; set; } = new();

    [XmlElement(ElementName = "MaximumFirmwareVersion")]
    public string MaximumFirmwareString { get; set; }

    [XmlElement(ElementName = "MinimumFirmwareVersion")]
    public string MinimumFirmwareString { get; set; }

    [XmlArray(ElementName = "Edition")]
    [XmlArrayItem(ElementName = "string")]
    public List<YubikeyEdition> Edition { get; set; } = new();

    [XmlArray(ElementName = "Slot")]
    [XmlArrayItem(ElementName = "string")]
    public List<string> Slot { get; set; } = new();

    [XmlArray(ElementName = "KeyAlgorithm")]
    [XmlArrayItem(ElementName = "string")]
    public List<KeyAlgorithmFamily> KeyAlgorithmFamilies { get; set; } = new();

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

    public string SaveToString()
    {
        var xmlSerializer = new XmlSerializer(typeof(YubikeyPolicy));

        using var stringWriter = new StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter);
        xmlSerializer.Serialize(xmlWriter, this);
        var xmlData = stringWriter.ToString();

        return ConvertToHumanReadableXml(xmlData);
    }
}