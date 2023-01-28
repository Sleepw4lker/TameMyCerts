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

namespace TameMyCerts.X509
{
    public class X509CertificateExtensionOcspMustStaple : X509CertificateExtension
    {
        public X509CertificateExtensionOcspMustStaple()
        {
            RawData = new byte[] { 0x30, 0x03, 0x02, 0x01, 0x05 };
        }
    }
}