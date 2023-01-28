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
using System.Linq;
using System.Text;

namespace TameMyCerts.X509
{
    public class X509CertificateExtensionAuthorityInformationAccess : X509CertificateExtension
    {
        private byte[] _uris = Array.Empty<byte>();

        public void AddUri(string uri, bool isOcsp = false)
        {
            // 1.3.6.1.5.5.7.48.1 or 1.3.6.1.5.5.7.48.2
            var node = isOcsp
                ? new byte[] {0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01}
                : new byte[] {0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02};

            node = node.Concat(Asn1BuildNode(0x86, Encoding.ASCII.GetBytes(uri))).ToArray();

            _uris = _uris.Concat(Asn1BuildNode(0x30, node)).ToArray();
        }

        public void InitializeEncode()
        {
            RawData = Asn1BuildNode(0x30, _uris);
        }
    }
}