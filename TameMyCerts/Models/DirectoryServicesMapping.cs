// Copyright 2021-2023 Uwe Gradenegger <uwe@gradenegger.eu>

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
using System.Xml.Serialization;

namespace TameMyCerts.Models
{
    // Must be public due to XML serialization, otherwise 0x80131509 / System.InvalidOperationException
    [XmlRoot(ElementName = "DirectoryServicesMapping")]
    public class DirectoryServicesMapping
    {
        [XmlElement(ElementName = "SearchRoot")]
        public string SearchRoot { get; set; }

        [XmlElement(ElementName = "CertificateAttribute")]
        public string CertificateAttribute { get; set; } = "userPrincipalName";

        [XmlElement(ElementName = "DirectoryServicesAttribute")]
        public string DirectoryServicesAttribute { get; set; } = "userPrincipalName";

        [XmlElement(ElementName = "ObjectCategory")]
        public string ObjectCategory { get; set; } = "user";

        [XmlArray(ElementName = "DirectoryObjectRules")]
        public List<DirectoryObjectRule> DirectoryObjectRules { get; set; } = new List<DirectoryObjectRule>();

        [XmlArray(ElementName = "AllowedSecurityGroups")]
        [XmlArrayItem(ElementName = "string")]
        public List<string> AllowedSecurityGroups { get; set; } = new List<string>();

        [XmlArray(ElementName = "DisallowedSecurityGroups")]
        [XmlArrayItem(ElementName = "string")]
        public List<string> DisallowedSecurityGroups { get; set; } = new List<string>();

        [XmlArray(ElementName = "AllowedOrganizationalUnits")]
        [XmlArrayItem(ElementName = "string")]
        public List<string> AllowedOrganizationalUnits { get; set; } = new List<string>();

        [XmlArray(ElementName = "DisallowedOrganizationalUnits")]
        [XmlArrayItem(ElementName = "string")]
        public List<string> DisallowedOrganizationalUnits { get; set; } = new List<string>();

        [XmlElement(ElementName = "PermitDisabledAccounts")]
        public bool PermitDisabledAccounts { get; set; }

        [XmlElement(ElementName = "SupplementServicePrincipalNames")]
        public bool SupplementServicePrincipalNames { get; set; }

        [XmlElement(ElementName = "AddSidUniformResourceIdentifier")]
        public bool AddSidUniformResourceIdentifier { get; set; }

        [XmlElement(ElementName = "MaximumPasswordAge")]
        public UInt32 MaximumPasswordAge { get; set; }
    }
}