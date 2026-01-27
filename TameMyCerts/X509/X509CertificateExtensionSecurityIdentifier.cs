// Copyright 2021-2025 Uwe Gradenegger <info@gradenegger.eu>

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
using System.Formats.Asn1;
using System.Security.Principal;
using System.Text;
using TameMyCerts.Enums;

namespace TameMyCerts.X509;

public class X509CertificateExtensionSecurityIdentifier : X509CertificateExtension
{
    /// <summary>
    ///     Creates a new X509 extension containing the SID as a string.
    /// </summary>
    /// <param name="sid">The security identifier to encode.</param>
    /// <exception cref="ArgumentNullException"></exception>
    public X509CertificateExtensionSecurityIdentifier(SecurityIdentifier sid)
    {
        ArgumentNullException.ThrowIfNull(sid);

        var asnWriter = new AsnWriter(AsnEncodingRules.DER);

        using (asnWriter.PushSequence())
        {
            using (asnWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                asnWriter.WriteObjectIdentifier(WinCrypt.szOID_NTDS_OBJECTSID);

                using (asnWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    asnWriter.WriteOctetString(Encoding.ASCII.GetBytes(sid.ToString()));
                }
            }
        }

        RawData = asnWriter.Encode();
    }
}