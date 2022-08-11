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

using System;
using System.IO;
using System.Linq;

namespace TameMyCerts
{
    public static class Asn1Tag
    {
        public const string OCTET_STRING = "04";
        public const string CONTEXT_SPECIFIC = "A0";
        public const string SEQUENCE = "30";
    }

    public class SidCertificateExtension
    {
        public readonly string value;

        public SidCertificateExtension(string sid)
        {
            var result = ConvertStringToDerNode(Asn1Tag.OCTET_STRING, ConvertStringToHexString(sid));
            result = ConvertStringToDerNode(Asn1Tag.CONTEXT_SPECIFIC, result);
            result = $"060A2B060104018237190201{result}"; // 1.3.6.1.4.1.311.25.2.1
            result = ConvertStringToDerNode(Asn1Tag.CONTEXT_SPECIFIC, result);
            result = ConvertStringToDerNode(Asn1Tag.SEQUENCE, result);
            result = Convert.ToBase64String(HexStringToByteArray(result));

            value = result;
        }

        private static byte[] HexStringToByteArray(string input)
        {
            var outputLength = input.Length / 2;
            var output = new byte[outputLength];
            using (var sr = new StringReader(input))
            {
                for (var i = 0; i < outputLength; i++)
                {
                    output[i] = Convert.ToByte(new string(new[] {(char) sr.Read(), (char) sr.Read()}), 16);
                }
            }

            return output;
        }

        private static string ConvertStringToDerNode(string identifier, string content)
        {
            return $"{identifier}{GetAsn1LengthOctets(content.Length)}{content}";
        }

        private static string ConvertStringToHexString(string content)
        {
            return content.ToCharArray().Aggregate("", (current, c) => current + $"{(int) c:X2}");
        }

        private static string GetAsn1LengthOctets(int length)
        {
            length = (int) Math.Ceiling(length / 2m);

            var numBits = Convert.ToString(length, 2).Length;
            var numOctets = Math.Ceiling(numBits / 8m);

            // Short form (for lengths between 0 and 127). One octet. 
            // Bit 8 has value "0" and bits 7-1 give the length.

            if (numBits <= 7)
            {
                return $"{length:X2}";
            }

            // Long form. Two to 127 octets.

            // Second and following octets give the length, base 256, most significant digit first.
            var result = string.Format("{0:X" + numOctets * 2 + "}", length);

            // Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets.
            return $"{(int) (128 + numOctets):X2}" + result;
        }
    }
}