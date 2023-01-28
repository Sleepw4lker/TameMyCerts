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
    public class X509CertificateExtensionCrlDistributionPoint : X509CertificateExtension
    {
        private byte[] _uris = Array.Empty<byte>();

        public void AddUri(string uri)
        {
            var result = Encoding.ASCII.GetBytes(uri);

            _uris = _uris.Concat(Asn1BuildNode(0x86, result)).ToArray();
        }

        public void InitializeEncode()
        {
            var result = _uris;

            result = Asn1BuildNode(0xA0, result);
            result = Asn1BuildNode(0xA0, result);
            result = Asn1BuildNode(0x30, result);
            result = Asn1BuildNode(0x30, result);

            RawData = result;
        }
    }
}