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

using System.Formats.Asn1;
using System.Security.Principal;
using System.Text;
using TameMyCerts.Enums;

namespace TameMyCerts.X509;

public class X509CertificateExtensionSecurityIdentifier : X509CertificateExtension
{
    public X509CertificateExtensionSecurityIdentifier(SecurityIdentifier sid)
    {
        var AsnWriter = new AsnWriter(AsnEncodingRules.DER);

        using (AsnWriter.PushSequence())
        {
            using (AsnWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                AsnWriter.WriteObjectIdentifier(WinCrypt.szOID_NTDS_OBJECTSID);

                using (AsnWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    AsnWriter.WriteOctetString(Encoding.ASCII.GetBytes(sid.ToString()));
                }
            }
        }

        RawData = AsnWriter.Encode();
    }
}