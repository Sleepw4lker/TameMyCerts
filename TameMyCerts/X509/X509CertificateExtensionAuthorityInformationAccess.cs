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
using System.Collections.Generic;
using System.Formats.Asn1;
using TameMyCerts.Enums;

namespace TameMyCerts.X509;

public class X509CertificateExtensionAuthorityInformationAccess : X509CertificateExtension
{
    private readonly List<KeyValuePair<Uri, bool>> _uris = [];

    public void AddUniformResourceIdentifier(string uri, bool isOcsp = false)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (Uri.TryCreate(uri, UriKind.Absolute, out var uriObject))
        {
            AddUniformResourceIdentifier(uriObject, isOcsp);
        }
    }

    public void AddUniformResourceIdentifier(Uri uri, bool isOcsp = false)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (!_uris.Exists(kvp => kvp.Key == uri && kvp.Value == isOcsp))
        {
            _uris.Add(new KeyValuePair<Uri, bool>(uri, isOcsp));
        }
    }

    public void InitializeEncode(bool encodeUris = false)
    {
        var asnWriter = new AsnWriter(AsnEncodingRules.DER);

        using (asnWriter.PushSequence())
        {
            foreach (var keyValuePair in _uris)
            {
                using (asnWriter.PushSequence())
                {
                    asnWriter.WriteObjectIdentifier(keyValuePair.Value
                        ? WinCrypt.szOID_PKIX_OCSP
                        : WinCrypt.szOID_PKIX_CA_ISSUERS);

                    asnWriter.WriteCharacterString(UniversalTagNumber.IA5String,
                        encodeUris ? EncodeUri(keyValuePair.Key.ToString()) : keyValuePair.Key.ToString(),
                        new Asn1Tag(TagClass.ContextSpecific, 6));
                }
            }
        }

        RawData = asnWriter.Encode();
    }
}