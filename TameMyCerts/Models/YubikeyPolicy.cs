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

using System.Collections.Generic;
using System.Xml.Serialization;

namespace TameMyCerts.Models
{
    // Must be public due to XML serialization, otherwise 0x80131509 / System.InvalidOperationException
    [XmlRoot(ElementName = "YubikeyPolicy")]
    public class YubikeyPolicy
    {
        [XmlArray(ElementName = "AllowedPinPolicies")]
        [XmlArrayItem(ElementName = "string")]
        public List<string> AllowedPinPolicies { get; set; } = new List<string>();
        [XmlArray(ElementName = "DisallowedPinPolicies")]
        [XmlArrayItem(ElementName = "string")]
        public List<string> DisallowedPinPolicies { get; set; } = new List<string>();
        [XmlArray(ElementName = "AllowedTouchPolicies")]
        [XmlArrayItem(ElementName = "string")]
        public List<string> AllowedTouchPolicies { get; set; } = new List<string>();
        [XmlArray(ElementName = "DisallowedTouchPolicies")]
        [XmlArrayItem(ElementName = "string")]
        public List<string> DisallowedTouchPolicies { get; set; } = new List<string>();
        [XmlArray(ElementName = "DisallowedFirmwareVersion")]
        [XmlArrayItem(ElementName = "string")]
        public List<string> DisallowedFirmwareVersion { get; set; } = new List<string>();
        [XmlArray(ElementName = "AllowedFirmwareVersion")]
        [XmlArrayItem(ElementName = "string")]
        public List<string> AllowedFirmwareVersion { get; set; } = new List<string>();
        [XmlElement(ElementName = "FIPSRequired")]
        public bool FIPSRequired { get; set; }

    }
}