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

using System.Collections.Generic;
using System.Xml.Serialization;

namespace TameMyCerts.Models
{
    // Must be public due to XML serialization, otherwise 0x80131509 / System.InvalidOperationException
    [XmlRoot(ElementName = "SubjectRule")]
    public class SubjectRule
    {
        [XmlElement(ElementName = "Field")]
        public string Field { get; set; } = string.Empty;

        [XmlElement(ElementName = "Mandatory")]
        public bool Mandatory { get; set; }

        [XmlElement(ElementName = "MaxOccurrences")]
        public int MaxOccurrences { get; set; } = 1;

        [XmlElement(ElementName = "MinLength")]
        public int MinLength { get; set; } = 1;

        [XmlElement(ElementName = "MaxLength")]
        public int MaxLength { get; set; } = 128;

        [XmlArray(ElementName = "Patterns")] 
        public List<Pattern> Patterns { get; set; } = new List<Pattern>();
    }
}