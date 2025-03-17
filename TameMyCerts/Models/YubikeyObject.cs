// Copyright 2021-2024 Uwe Gradenegger <uwe@gradenegger.eu>
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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using TameMyCerts.Enums;

namespace TameMyCerts.Models;

// Must be public due to XML serialization, otherwise 0x80131509 / System.InvalidOperationException
[XmlRoot(ElementName = "YubiKeyObject")]
public class YubikeyObject
{
    private const string AttestationSlotPattern = @"CN=YubiKey PIV Attestation (?<slot>[0-9A-Fa-f]{2})";

    public YubikeyObject()
    {
    }

    public YubikeyObject(byte[] publicKey, X509Certificate2 attestationCertificate,
        X509Certificate2 intermediateCertificate, X509Certificate2Collection rootCertificates,
        KeyAlgorithmFamily keyAlgorithm, int keyLength, int requestId)
    {
        var chain = new X509Chain();

        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(rootCertificates);

        // Note that according to Yubikey docs, there is always exactly one intermediate certificate
        chain.ChainPolicy.ExtraStore.Add(intermediateCertificate);

        // Note that neither certificate in this chain has a CRLDP, so no need to worry about that
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        if (!chain.Build(attestationCertificate))
        {
            ETWLogger.Log.YKVal_4208_Yubikey_Attestion_Failed_to_build(requestId);
            throw new Exception("Failed to build certificate chain.");
        }

        if (!publicKey.SequenceEqual(chain.ChainElements[0].Certificate.PublicKey.EncodedKeyValue.RawData))
        {
            ETWLogger.Log.YKVal_4207_Yubikey_Attestion_Missmatch_with_CSR(requestId);
            throw new Exception("Certificate Signing Request does not match attestation certificate.");
        }

        Validated = true;

        #region Slot

        // the Slot number is located in the Subject for the Attestation certificate.

        var slotRegex = new Regex(AttestationSlotPattern);
        var slotMatch = slotRegex.Match(attestationCertificate.Subject);
        if (slotMatch.Success)
        {
            Slot = slotMatch.Groups["slot"].Value;
        }

        #endregion

        #region PIN / touch policy

        var pinTouchPolicy = attestationCertificate.Extensions
            .FirstOrDefault(x => x.Oid.Value == "1.3.6.1.4.1.41482.3.8")?.RawData;
        if (pinTouchPolicy.Length == 2)
        {
            // Staring with the PIN Policy
            PinPolicy = (YubikeyPinPolicy)pinTouchPolicy[0];
            // Update the TouchPolicy
            TouchPolicy = (YubikeyTouchPolicy)pinTouchPolicy[1];
        }

        #endregion

        #region FormFactor

        var formFactor = attestationCertificate.Extensions
            .FirstOrDefault(x => x.Oid.Value == YubikeyX509Extensions.FORMFACTOR)?.RawData[0] ?? 0;
        FormFactor =
            (YubikeyFormFactor)(formFactor & 0x0F); // Mask out the upper 4 bits, Those are used for CSPN and FIPS

        #endregion

        #region Firmware Version

        // Update the Firmware Version
        var firmwareVersion = attestationCertificate.Extensions
            .FirstOrDefault(x => x.Oid.Value == YubikeyX509Extensions.FIRMWARE)?.RawData;
        if (firmwareVersion.Length == 3)
        {
            FirmwareVersion = new Version(firmwareVersion[0], firmwareVersion[1], firmwareVersion[2]);
        }

        #endregion

        #region Serial Number

        // Update the Serial Number
        var serialNumber = attestationCertificate.Extensions
            .FirstOrDefault(x => x.Oid.Value == YubikeyX509Extensions.SERIALNUMBER)?.RawData;
        if (serialNumber is not null)
        {
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(serialNumber);
            }

            SerialNumber = BitConverter.ToUInt32(serialNumber, 0).ToString();
        }

        #endregion

        #region FIPS / CSPN

        // Check for the FIPS extension
        if (intermediateCertificate.Extensions.Any(x => x.Oid.Value == YubikeyX509Extensions.FIPS_CERTIFIED))
        {
            Edition = YubikeyEdition.FIPS;
        }
        else if (intermediateCertificate.Extensions
                 .Any(x => x.Oid.Value == YubikeyX509Extensions.CPSN_CERTIFIED))
        {
            Edition = YubikeyEdition.CSPN;
        }

        #endregion

        #region Key Algorithm and length for Policy use

        KeyAlgorithm = keyAlgorithm;
        KeyLength = keyLength;

        #endregion

        #region Lets save the certificates, if needed for the future

        AttestationCertificate = attestationCertificate;
        IntermediateCertificate = intermediateCertificate;

        #endregion

        // Add to the attributes to allow for replacement
        Attributes.Add("FormFactor", FormFactor.ToString());
        Attributes.Add("FirmwareVersion", FirmwareVersion.ToString());
        Attributes.Add("PinPolicy", PinPolicy.ToString());
        Attributes.Add("TouchPolicy", TouchPolicy.ToString());
        Attributes.Add("Slot", Slot);
        Attributes.Add("SerialNumber", SerialNumber);
    }

    [XmlIgnore]
    public Dictionary<string, string> Attributes { get; } =
        new(StringComparer.InvariantCultureIgnoreCase);

    [XmlElement(ElementName = "TouchPolicy")]
    public YubikeyTouchPolicy TouchPolicy { get; set; }

    [XmlElement(ElementName = "PinPolicy")]
    public YubikeyPinPolicy PinPolicy { get; set; }

    [XmlElement(ElementName = "FormFactor")]
    public YubikeyFormFactor FormFactor { get; set; }

    [XmlElement(ElementName = "Slot")] public string Slot { get; set; } = "";

    [XmlElement(ElementName = "Serial")] public string SerialNumber { get; set; } = "";

    [XmlElement(ElementName = "FirmwareVersion")]
    public string FirmwareVersionString
    {
        get => FirmwareVersion.ToString();
        set => throw new Exception("String cannot be set.");
    }

    [XmlIgnore] public Version FirmwareVersion { get; set; } = new(0, 0, 0);

    [XmlElement(ElementName = "KeyAlgorithm")]
    public KeyAlgorithmFamily KeyAlgorithm { get; set; }

    [XmlElement(ElementName = "KeyLength")]
    public int KeyLength { get; set; }

    [XmlElement(ElementName = "Edition")] public YubikeyEdition Edition { get; set; } = YubikeyEdition.Normal;

    [XmlIgnore] public X509Certificate2 AttestationCertificate { get; }

    [XmlIgnore] public X509Certificate2 IntermediateCertificate { get; }

    [XmlElement(ElementName = "Validated")]
    public bool? Validated { get; } = false;

    public static string ConvertToHumanReadableXml(string inputString)
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
        var xmlSerializer = new XmlSerializer(typeof(YubikeyObject));

        using var stringWriter = new StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter);
        xmlSerializer.Serialize(xmlWriter, this);
        var xmlData = stringWriter.ToString();

        return ConvertToHumanReadableXml(xmlData);
    }
}