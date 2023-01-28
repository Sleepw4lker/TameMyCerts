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
using System.Collections.Generic;
using System.Linq;
using TameMyCerts.ClassExtensions;

namespace TameMyCerts.X509
{
    public abstract class X509CertificateExtension
    {
        public byte[] RawData { get; internal set; } = Array.Empty<byte>();

        internal byte[] Asn1BuildNode(byte identifier, byte[] content)
        {
            var result = new[] {identifier};

            result = result.Concat(Asn1GetLength(content.Length)).ToArray();
            result = result.Concat(content).ToArray();

            return result;
        }

        private static IEnumerable<byte> Asn1GetLength(int numDataOctets)
        {
            // Short form (for lengths between 0 and 127). One octet. 
            // Bit 8 has value "0" and bits 7-1 give the length.

            // Note that BitConverter.GetBytes always returns 32 Bit = 4 Bytes
            if (numDataOctets <= 127)
            {
                return BitConverter.GetBytes(numDataOctets).TrimEnd();
            }

            // Long form. Two to 127 octets.
            // Second and following octets give the length, base 256, most significant digit first.

            var lengthOctets = BitConverter.GetBytes(numDataOctets).TrimEnd().Reverse().ToArray();
            
            // Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets.
            return new[] {(byte) (0x80 | lengthOctets.Length)}.Concat(lengthOctets).ToArray();
        }
    }
}