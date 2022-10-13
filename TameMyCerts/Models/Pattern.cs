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

using System.Net;
using System.Text.RegularExpressions;
using TameMyCerts.ClassExtensions;

namespace TameMyCerts.Models
{
    // Must be public due to XML serialization, otherwise 0x80131509 / System.InvalidOperationException
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